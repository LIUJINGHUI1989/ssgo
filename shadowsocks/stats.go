package shadowsocks

import (
    "sync"
    "time"
    "fmt"
)

var Stats map[string]*PortStats

type PortStats struct {
    sync.Mutex
    D int64
    U int64
    De int64
    Ue int64
    T int64
}



func InitStats() {
    Stats = make(map[string]*PortStats)
}

func updateU(port string,u int) {
    stat, ok := Stats[port]
    if !ok {
        panic(fmt.Errorf("Port: %s 's stat doesn't exist!",port))
    }
    stat.Lock()
    defer stat.Unlock()
    if (u>0) {
        stat.U += int64(u)
        stat.Ue += 534
        stat.T = time.Now().Unix()
    }
}

func updateD(port string,d int) {
    stat, ok := Stats[port]
    if !ok {
        panic(fmt.Errorf("Port: %s 's stat doesn't exist!",port))
    }
    stat.Lock()
    defer stat.Unlock()
    if (d>0) {
        stat.D += int64(d)
        stat.De += 534
        stat.T = time.Now().Unix()
    }
}

func AddStat(port string) {
    var mutex sync.Mutex    
    mutex.Lock()
    defer mutex.Unlock()
    _, ok := Stats[port]
    if !ok {
        Debug.Printf("updateStat port:%s record not found! Add!",port)
        Stats[port] = &PortStats{U:0,D:0,T:0}
        Debug.Printf("addStat: port:%s",port)
    }
}