package shadowsocks

import (
    "sync"
    "time"
)

var Stats map[string]*PortStats

type PortStats struct {
    sync.Mutex
    D int64
    U int64
    T int64
}



func InitStats() {
    Stats = make(map[string]*PortStats)
}


func updateUDT(port string,u int,d int) {
    stat, ok := Stats[port]
    if !ok {
		Debug.Printf("updateStat port:%s record not found! Add!",port)
		addStat(port,u,d)
	} else {
        t := time.Now().Unix()
		stat.Lock()
		Debug.Printf("updateStat port:%s. u:%d d:%d t:%d", port,u,d,t)

		Debug.Printf("Before: port:%s. u:%d d:%d t:%d", port,stat.U,stat.D,stat.T)
		stat.U += int64(u)
        stat.D += int64(d)
		stat.T = t
		Debug.Printf("After: port:%s. u:%d d:%d t:%d", port,stat.U,stat.D,stat.T)
		stat.Unlock()
	}
}

func addStat(port string,u int,d int) {
    var mutex sync.Mutex
    
    mutex.Lock()
    defer mutex.Unlock()
    
    stat, ok := Stats[port]
    t:=time.Now().Unix()
    if !ok {
        Debug.Printf("updateStat port:%s record not found! Add!",port)
        Stats[port] = &PortStats{U:int64(u),D:int64(d),T:t}
        Debug.Printf("addStat: port:%s u:%d d:%d t:%d",port,u,d,t)
    } else {
        Debug.Printf("[ERR addStat to updateStat] port:%s. u:%d d:%d t:%d", port,u,d,t)
        Debug.Printf("Before: port:%s. u:%d d:%d t:%d", port,stat.U,stat.D,stat.T)
        stat.U += int64(u)
        stat.D += int64(d)
		stat.T = t
        Debug.Printf("After: port:%s. u:%d d:%d t:%d", port,stat.U,stat.D,stat.T)
    }
}