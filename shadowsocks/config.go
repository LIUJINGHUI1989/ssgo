package shadowsocks

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	// "log"
	"os"
	"reflect"
	"strings"
	"time"
	"net/http"
	"math/rand"
)

type Config struct {
	Method     string      `json:"method"` // encryption method
	Auth       bool        `json:"auth"`   // one time auth

	// following options are only used by server
	PortPassword map[string]string `json:"port_password"`
	Timeout      int               `json:"timeout"`

	// following options are only used by client

	// The order of servers in the client config is significant, so use array
	// instead of map to preserve the order.
	ServerPassword [][]string `json:"server_password"`

	DatabaseHost string	`json:"dbhost"`
	DatabasePort string	`json:"dbport"`
	DatabaseUnix string	`json:"dbunix"`
	DatabaseUser string	`json:"dbuser"`
	DatabasePass string	`json:"dbpass"`
	DatabaseName string	`json:"dbname"`

	ServerTag string	`json:"servertag"`
	ServerAddr string	`json:"serveraddr"`
	ServerID int64
}
var readTimeout time.Duration

func ParseConfig(path string,db *sql.DB) (config *Config, err error) {
	file, err := os.Open(path) // For read access.
	if err != nil {
		return
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return
	}
	config = &Config{}
	if err = json.Unmarshal(data, config); err != nil {
		return nil, err
	}
	if config.ServerTag == "" {
		return nil,fmt.Errorf("you must define a servertag. T:[%s]",config.ServerTag)
	}
	if db==nil {
		Debug.Printf("db is nil, init new connection [%v]",db)
		if config.DatabaseUser == "" || config.DatabaseName == "" {
			return nil,fmt.Errorf("db config auth error: U:%s P:%s N:%s",config.DatabaseUser,config.DatabasePass,config.DatabaseName)
		}
		if (config.DatabaseHost =="" || config.DatabasePort =="") && config.DatabaseUnix!="" {
			return nil,fmt.Errorf("db connection error H:%s P:%s U:%s",config.DatabaseHost,config.DatabasePort,config.DatabaseUnix)
		}
		var dsn,dsnconn string
		if (config.DatabaseUnix!="") {
			Debug.Println("db config: socket found, ignore host and port")
			dsnconn = fmt.Sprintf("unix(%s)",config.DatabaseUnix)
		} else {
			Debug.Println("db config: use tcp")
			dsnconn = fmt.Sprintf("tcp(%s:%s)",config.DatabaseHost,config.DatabasePort)
		}		
		if config.DatabasePass != "" {
			dsn = fmt.Sprintf("%s:%s@%s/%s?charset=utf8",config.DatabaseUser,config.DatabasePass,dsnconn,config.DatabaseName)
		} else {
			dsn = fmt.Sprintf("%s@%s/%s?charset=utf8",config.DatabaseUser,dsnconn,config.DatabaseName)
		}
		Debug.Printf("preparing to connect to mysql via dsn:[%v]",dsn)
		db, err = sql.Open("mysql", dsn)
		if err!=nil {
			return nil,err
		}
		Debug.Println("mysql connected")
		db.SetMaxOpenConns(70)
		db.SetMaxIdleConns(10)
		
	}
	//check server info exist in db. if not, check extern ip to register it.
	err = chkServer(db,config)
	if (err!=nil) {
		return nil,err
	}
	//start connect to db to fetch users to port_password
	pps,err := fetchUsers(db)
	if err!=nil {
		return nil,err
	}
	config.PortPassword=pps
	readTimeout = time.Duration(config.Timeout) * time.Second
	if strings.HasSuffix(strings.ToLower(config.Method), "-auth") {
		config.Method = config.Method[:len(config.Method)-5]
		config.Auth = true
	}
	return
}

func chkServer(db *sql.DB,config *Config) error {
	stmt, err :=  db.Prepare("SELECT * FROM ss_server WHERE name = ? LIMIT 1;")
	if err != nil {
		return err
	}
	row := stmt.QueryRow(config.ServerTag)
	err = row.Scan(&config.ServerID,&config.ServerTag,&config.ServerAddr)
	if err == nil {
		return nil
	}
	if err != sql.ErrNoRows {
		return err
	}
	if config.ServerAddr != "" {
		stmt, err = db.Prepare("INSERT INTO ss_server (name,addr) values (?,?);")
		if err!=nil {
			return err
		}
		r, err := stmt.Exec(config.ServerTag,config.ServerAddr)
		if err!=nil {
			return err
		}
		config.ServerID, err = r.LastInsertId()
		return err
	} else {
		resp, err := http.Get("http://whatismyip.akamai.com/")
		defer resp.Body.Close()
		if err!=nil {
			return fmt.Errorf("Cannot get server ext ip (via akamai). Please define serveraddr in config file instead.")
		}
		body, err := ioutil.ReadAll(resp.Body)
		if err!= nil {
			return fmt.Errorf("Get ext ip failed. Akamai return an error result")
		}
		config.ServerAddr = string(body)
		return nil
	}
}

func fetchUsers(db *sql.DB,config *Config) (map[string]string,error) {
	pps := make(map[string]string)
	db.Exec("UPDATE ss_user SET active = 1 where u + d < limits and active=0;")
	db.Exec("UPDATE ss_user SET active = 0 where u + d >= limits and active=1;")
	db.Exec("DELETE from ss_user where email='keepalive@server' or port='18181';")
	stmt, err := db.Prepare("INSERT INTO ss_user (name,email,port,passwd,limits,active) values ('keepalive','keepalive@server',18181,?,100000000000,1);")
	if err != nil {
		return nil,err
	}
	stmt.Exec(Krand(16,3))
	if err !=nil {
		return nil,err
	}
	stmt.Close()
	db.Exec(fmt.Sprintf("INSERT IGNORE INTO ss_detail (server_id, user_id) SELECT %d, id FROM ss_user WHERE active = 1",config.ServerID))   
	rows, err := db.Query("SELECT port,passwd FROM ss_user WHERE active = 1;")
    if err != nil {
        return nil,err
    }
	for rows.Next() {
        var k,v string
        err = rows.Scan(&k, &v)
		if k=="" || v=="" {
			continue
		}
		pps[k]=v
    }
	return pps,nil
}


func SetDebug(d DebugLog) {
	Debug = d
}

// Useful for command line to override options specified in config file
// Debug is not updated.
func UpdateConfig(old, new *Config) {
	// Using reflection here is not necessary, but it's a good exercise.
	// For more information on reflections in Go, read "The Laws of Reflection"
	// http://golang.org/doc/articles/laws_of_reflection.html
	newVal := reflect.ValueOf(new).Elem()
	oldVal := reflect.ValueOf(old).Elem()

	// typeOfT := newVal.Type()
	for i := 0; i < newVal.NumField(); i++ {
		newField := newVal.Field(i)
		oldField := oldVal.Field(i)
		// log.Printf("%d: %s %s = %v\n", i,
		// typeOfT.Field(i).Name, newField.Type(), newField.Interface())
		switch newField.Kind() {
		case reflect.Interface:
			if fmt.Sprintf("%v", newField.Interface()) != "" {
				oldField.Set(newField)
			}
		case reflect.String:
			s := newField.String()
			if s != "" {
				oldField.SetString(s)
			}
		case reflect.Int:
			i := newField.Int()
			if i != 0 {
				oldField.SetInt(i)
			}
		}
	}

	old.Timeout = new.Timeout
	readTimeout = time.Duration(old.Timeout) * time.Second
}

//Krand rand string，kind: 0 number 1 lowercase 2 uppercase 3 all before
func Krand(size int, kind int) string {
    ikind, kinds, result := kind, [][]int{[]int{10, 48}, []int{26, 97}, []int{26, 65}}, make([]byte, size)
    isall := kind > 2 || kind < 0
    rand.Seed(time.Now().UnixNano())
    for i :=0; i < size; i++ {
        if isall { // random ikind
            ikind = rand.Intn(3)
        }
        scope, base := kinds[ikind][0], kinds[ikind][1]
        result[i] = uint8(base+rand.Intn(scope))
    }
    return string(result)
}