package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"net/http"
	"time"
	_ "github.com/go-sql-driver/mysql"
	"database/sql"
	ss "github.com/realpg/ssgo/shadowsocks"
)

const (
	idType  = 0 // address type index
	idIP0   = 1 // ip addres start index
	idDmLen = 1 // domain address length index
	idDm0   = 2 // domain address start index

	typeIPv4 = 1 // type is ipv4 address
	typeDm   = 3 // type is domain address
	typeIPv6 = 4 // type is ipv6 address

	lenIPv4     = net.IPv4len + 2 // ipv4 + 2port
	lenIPv6     = net.IPv6len + 2 // ipv6 + 2port
	lenDmBase   = 2               // 1addrLen + 2port, plus addrLen
	lenHmacSha1 = 10
)

var debug ss.DebugLog
var db *sql.DB
var dbfile *os.File

func getRequest(conn *ss.Conn, auth bool) (host string, ota bool, err error) {
	ss.SetReadTimeout(conn)

	// buf size should at least have the same size with the largest possible
	// request size (when addrType is 3, domain name has at most 256 bytes)
	// 1(addrType) + 1(lenByte) + 256(max length address) + 2(port) + 10(hmac-sha1)
	buf := make([]byte, 270)
	// read till we get possible domain length field
	if _, err = io.ReadFull(conn, buf[:idType+1]); err != nil {
		return
	}

	var reqStart, reqEnd int
	addrType := buf[idType]
	switch addrType & ss.AddrMask {
	case typeIPv4:
		reqStart, reqEnd = idIP0, idIP0+lenIPv4
	case typeIPv6:
		reqStart, reqEnd = idIP0, idIP0+lenIPv6
	case typeDm:
		if _, err = io.ReadFull(conn, buf[idType+1:idDmLen+1]); err != nil {
			return
		}
		reqStart, reqEnd = idDm0, int(idDm0+buf[idDmLen]+lenDmBase)
	default:
		err = fmt.Errorf("addr type %d not supported", addrType&ss.AddrMask)
		return
	}

	if _, err = io.ReadFull(conn, buf[reqStart:reqEnd]); err != nil {
		return
	}

	// Return string for typeIP is not most efficient, but browsers (Chrome,
	// Safari, Firefox) all seems using typeDm exclusively. So this is not a
	// big problem.
	switch addrType & ss.AddrMask {
	case typeIPv4:
		host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
	case typeIPv6:
		host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
	case typeDm:
		host = string(buf[idDm0 : idDm0+buf[idDmLen]])
	}
	// parse port
	port := binary.BigEndian.Uint16(buf[reqEnd-2 : reqEnd])
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	// if specified one time auth enabled, we should verify this
	if auth || addrType&ss.OneTimeAuthMask > 0 {
		ota = true
		if _, err = io.ReadFull(conn, buf[reqEnd:reqEnd+lenHmacSha1]); err != nil {
			return
		}
		iv := conn.GetIv()
		key := conn.GetKey()
		actualHmacSha1Buf := ss.HmacSha1(append(iv, key...), buf[:reqEnd])
		if !bytes.Equal(buf[reqEnd:reqEnd+lenHmacSha1], actualHmacSha1Buf) {
			err = fmt.Errorf("verify one time auth failed, iv=%v key=%v data=%v", iv, key, buf[:reqEnd])
			return
		}
	}
	return
}

const logCntDelta = 100

var connCnt int
var nextLogConnCnt int = logCntDelta

func handleConnection(conn *ss.Conn, auth bool) {
	var host string

	connCnt++ // this maybe not accurate, but should be enough
	if connCnt-nextLogConnCnt >= 0 {
		// XXX There's no xadd in the atomic package, so it's difficult to log
		// the message only once with low cost. Also note nextLogConnCnt maybe
		// added twice for current peak connection number level.
		log.Printf("Number of client connections reaches %d\n", nextLogConnCnt)
		nextLogConnCnt += logCntDelta
	}

	// function arguments are always evaluated, so surround debug statement
	// with if statement
	if debug {
		debug.Printf("new client %s->%s\n", conn.RemoteAddr().String(), conn.LocalAddr())
	}
	closed := false
	defer func() {
		if debug {
			debug.Printf("closed pipe %s<->%s\n", conn.RemoteAddr(), host)
		}
		connCnt--
		if !closed {
			conn.Close()
		}
	}()

	host, ota, err := getRequest(conn, auth)
	if err != nil {
		log.Println("error getting request", conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}
	debug.Println("connecting", host)
	remote, err := net.Dial("tcp", host)
	if err != nil {
		if ne, ok := err.(*net.OpError); ok && (ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE) {
			// log too many open file error
			// EMFILE is process reaches open file limits, ENFILE is system limit
			log.Println("dial error:", err)
		} else {
			log.Println("error connecting to:", host, err)
		}
		return
	}
	defer func() {
		if !closed {
			remote.Close()
		}
	}()
	if debug {
		debug.Printf("piping %s<->%s ota=%v connOta=%v", conn.RemoteAddr(), host, ota, conn.IsOta())
	}
	if ota {
		go ss.PipeThenCloseOta(conn, remote)
	} else {
		go ss.PipeThenClose1(conn, remote)
	}
	ss.PipeThenClose2(remote, conn)
	closed = true
	return
}


type PortListener struct {
	password string
	listener net.Listener
}

type PasswdManager struct {
	sync.Mutex
	portListener map[string]*PortListener
}

func (pm *PasswdManager) add(port, password string, listener net.Listener) {
	pm.Lock()
	pm.portListener[port] = &PortListener{password, listener}
	pm.Unlock()
}

func (pm *PasswdManager) get(port string) (pl *PortListener, ok bool) {
	pm.Lock()
	pl, ok = pm.portListener[port]
	pm.Unlock()
	return
}

func (pm *PasswdManager) del(port string) {
	pl, ok := pm.get(port)
	if !ok {
		return
	}
	pl.listener.Close()
	pm.Lock()
	delete(pm.portListener, port)
	pm.Unlock()
}

// Update port password would first close a port and restart listening on that
// port. A different approach would be directly change the password used by
// that port, but that requires **sharing** password between the port listener
// and password manager.
func (pm *PasswdManager) updatePortPasswd(port, password string, auth bool) {
	pl, ok := pm.get(port)
	if !ok {
		log.Printf("new port %s added\n", port)
	} else {
		if pl.password == password {
			return
		}
		log.Printf("closing port %s to update password\n", port)
		pl.listener.Close()
	}
	// run will add the new port listener to passwdManager.
	// So there maybe concurrent access to passwdManager and we need lock to protect it.
	go run(port, password, auth)
}

var passwdManager = PasswdManager{portListener: map[string]*PortListener{}}

func updatePasswd() {
	log.Println("updating password")
	newconfig, err := ss.ParseConfig(configFile,db)
	if err != nil {
		log.Printf("error parsing config file %s to update password: %v\n", configFile, err)
		return
	}
	oldconfig := config
	config = newconfig

	if err = unifyPortPassword(config); err != nil {
		return
	}
	for port, passwd := range config.PortPassword {
		passwdManager.updatePortPasswd(port, passwd, config.Auth)
		if oldconfig.PortPassword != nil {
			delete(oldconfig.PortPassword, port)
		}
	}
	// port password still left in the old config should be closed
	for port, _ := range oldconfig.PortPassword {
		log.Printf("closing port %s as it's deleted\n", port)
		passwdManager.del(port)
	}
	log.Println("password updated")
}

func waitSignal() {
	var sigChan = make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)
	for sig := range sigChan {
		if sig == syscall.SIGHUP {
			updatePasswd()
		} else {
			// is this going to happen?
			log.Printf("caught signal %v, exit", sig)
			os.Exit(0)
		}
	}
}

func run(port, password string, auth bool) {
	ss.AddStat(port)
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Printf("error listening port %v: %v\n", port, err)
		os.Exit(1)
	}
	passwdManager.add(port, password, ln)
	var cipher *ss.Cipher
	log.Printf("server listening port %v ...\n", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			// listener maybe closed to update password
			debug.Printf("accept error: %v\n", err)
			return
		}
		// Creating cipher upon first connection.
		if cipher == nil {
			log.Println("creating cipher for port:", port)
			cipher, err = ss.NewCipher(config.Method, password)
			if err != nil {
				log.Printf("Error generating cipher for port: %s %v\n", port, err)
				conn.Close()
				continue
			}
		}
		go handleConnection(ss.NewConn(conn, cipher.Copy(),port), auth)
	}
}


func unifyPortPassword(config *ss.Config) (err error) {
	if len(config.PortPassword) == 0 { // this handles both nil PortPassword and empty one
		fmt.Fprintln(os.Stderr, "no port_password loaded")
		return errors.New("There are no active users in db.")
	}
	return
}


var configFile string
var config *ss.Config

func main() {
	log.SetOutput(os.Stdout)
	var cmdConfig ss.Config
	var printVer bool
	var core int

	flag.BoolVar(&printVer, "v", false, "show version and about")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.IntVar(&cmdConfig.Timeout, "t", 300, "timeout in seconds, default 300")
	flag.StringVar(&cmdConfig.Method, "m", "", "encryption, default:aes-128-cfb")
	flag.IntVar(&core, "core", 0, "maximum number of CPU cores to use, default is determinied by Go runtime")
	flag.BoolVar((*bool)(&debug), "d", false, " ")
	flag.Parse()
	ss.InitStats()

	if printVer {
		ss.PrintVersion()
		os.Exit(0)
	}
	
	dbfile,err := os.OpenFile("dbfail.log",os.O_CREATE|os.O_APPEND,0660)
	if err!=nil {
		fmt.Println("Cannot open db-failsafe log file [dbfail.log]. Please check write permission!")
		os.Exit(1)
	}
	defer dbfile.Close()

	ss.SetDebug(debug)

	if strings.HasSuffix(cmdConfig.Method, "-auth") {
		cmdConfig.Method = cmdConfig.Method[:len(cmdConfig.Method)-5]
		cmdConfig.Auth = true
	}

	config, err = ss.ParseConfig(configFile,db)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", configFile, err)
			os.Exit(1)
		}
		config = &cmdConfig
	} else {
		ss.UpdateConfig(config, &cmdConfig)
	}
	if config.Method == "" {
		config.Method = "aes-128-cfb"
	}
	if err = ss.CheckCipherMethod(config.Method); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err = unifyPortPassword(config); err != nil {
		os.Exit(1)
	}
	if core > 0 {
		runtime.GOMAXPROCS(core)
	}
	for port, password := range config.PortPassword {
		go run(port, password, config.Auth)
	}
	defer save2DB(2)
	http.HandleFunc("/", statusPage)
	http.ListenAndServe(":7777", nil)
	go saveStat()
	waitSignal()
}

func statusPage(w http.ResponseWriter, req *http.Request) {
	str := fmt.Sprintf("ShadowSocks Server Stat:\n\nDBPool: %d\n\n",db.Stats().OpenConnections)
	for port,stat:=range ss.Stats  {
		str += fmt.Sprintf("Port: %s\t U: %v(%v) D: %v(%v) T: %v\n",port,readable(stat.U),readable(stat.U+stat.Ue),readable(stat.D),readable(stat.D+stat.De),time.Unix(stat.T,0).Format("2006-01-02 15:04:05"))	 
	} 
	io.WriteString(w, str)
}
func readable(bytes int64) string {
	float:=float64(bytes)
	
	switch  {
		case bytes > 1073741824 :
			return fmt.Sprintf("%.2f GB",(float/1073741824.0))
		case bytes > 1048576 :
			return fmt.Sprintf("%.2f MB",(float/1048576.0))
		case bytes > 1024 :
			return fmt.Sprintf("%.2f KB",(float/1024.0))
		default:
			return fmt.Sprintf("%d Bytes",bytes)
	}
}


func saveStat() {
    timer := time.NewTimer(14 * time.Second)
    for {
        <-timer.C
		debug.Println("[timer] saving stats to db")
        save2DB(0)
        timer.Reset(14 * time.Second)
    }
}

func save2DB(r int) {
	if r==2 {
		fmt.Println("Stop signal received! Dumping stat to database!")
	}
	sqlpp := "UPDATE ss_user SET u = CASE port"
	sqlpu := "UPDATE ss_detail SET u = CASE user_id" //WHERE server_id = {{config.ServerID}} 
	var whenpp1,whenpp2,whenpp3,whenpp4,whenpu1,whenpu2,whenpu3,whenpu4,inpp,inpu string
	t := time.Now().Unix()
	i := 0
	for port,stat:=range ss.Stats {
		if stat.U==0 {
			debug.Printf("[dump2db] port %s upstream data 0, skipped. U:%d D:%d Ue:%d De:%d",port,stat.U,stat.D,stat.Ue,stat.De)
			continue
		}
		i++
		u := stat.U;	d := stat.D;	ue := stat.Ue;	de := stat.De;	
		stat.U -= u;	stat.D -= d;	stat.Ue -= ue;	stat.De -= de;
		whenpp1 += fmt.Sprintf(" WHEN %v THEN u+%v",port,u)
		whenpp2 += fmt.Sprintf(" WHEN %v THEN d+%v",port,d)
		whenpp3 += fmt.Sprintf(" WHEN %v THEN ue+%v",port,ue)
		whenpp4 += fmt.Sprintf(" WHEN %v THEN de+%v",port,de)
		
		whenpu1 += fmt.Sprintf(" WHEN %v THEN u+%v",config.PortUID[port],u)
		whenpu2 += fmt.Sprintf(" WHEN %v THEN d+%v",config.PortUID[port],d)
		whenpu3 += fmt.Sprintf(" WHEN %v THEN ue+%v",config.PortUID[port],ue)
		whenpu4 += fmt.Sprintf(" WHEN %v THEN de+%v",config.PortUID[port],de)
		if inpp=="" {
			inpp = port
			inpu = config.PortUID[port]
		} else {
			inpp += fmt.Sprintf(",%s",port)
			inpu += fmt.Sprintf(",%s",config.PortUID[port])
		}
	}
	if i==0 {
		debug.Println("All ports have no new traffics. Skipping save to database.")
		return
	}
	sqlpp += whenpp1 + " END, d = CASE port" + whenpp2 + " END, ue = CASE port" + whenpp3 + " END, de = CASE port" + whenpp4
	sqlpp += fmt.Sprintf(" END, t = %v WHERE port IN (%s);",t,inpp)
	debug.Println("SQL-pp:",sqlpp)
	sqlpu += whenpu1 + " END, d = CASE port" + whenpu2 + " END, ue = CASE port" + whenpu3 + " END, de = CASE port" + whenpu4
	sqlpu += fmt.Sprintf(" END, t = %v WHERE port IN (%s) AND server_id = %v;",t,inpu,config.ServerID)
	debug.Println("SQL-pu:",sqlpu)
	
	_,err := db.Exec(sqlpp)
	if (err!=nil) {
		dbFail(sqlpp,err)
	}
	_,err = db.Exec(sqlpu)
	if (err!=nil) {
		dbFail(sqlpu,err)
	}
}

func dbFail(sql string,err error) {
	fmt.Printf("[save2db]Fail to execute sql (ERR:%s), saving to failsafe log",err.Error())
	_,err = dbfile.WriteString(fmt.Sprintf("### %s\n",time.Now().Format("2006-01-02 15:04:05")))
	if err!=nil {
		fmt.Println("Error writing db failsafe file [dbfail.log], system will exit")
		os.Exit(1)
	}
	_,err = dbfile.WriteString(fmt.Sprintf("%s\n###end\n",sql))
	if err!=nil {
		fmt.Println("Error writing db failsafe file [dbfail.log], system will exit")
		os.Exit(1)
	}
}