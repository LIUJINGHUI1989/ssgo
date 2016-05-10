package utils

import (
    "crypto/md5"
    "crypto/sha1"
    "math/rand"
    "time"
    "fmt"
    "os"
)
var salt = "QuickSS, a free ss system."


func G(n,p string) (string){
    v1 := md5.Sum(Krand(64,3))
    v1s := fmt.Sprintf("%x",v1)
    t1s := v1s + n + p + salt
    t1h := sha1.Sum([]byte(t1s))
    t1hs := fmt.Sprintf("%x",t1h)
    return v1s + t1hs
}

func V(n,p,hash string) bool {
    v2s := SubString(hash,0,32)
    t2s := v2s + n + p + salt
    t2h := sha1.Sum([]byte(t2s))
    t2hs := fmt.Sprintf("%x",t2h)
    h2 := v2s + t2hs
    return h2 == hash
}


//Krand rand []byte，kind: 0 number 1 lowercase 2 uppercase 3 all before
func Krand(size int, kind int) []byte {
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
    return result
}

func Test(n,p string) {
    fmt.Printf("TAU: %s TAP: %s\n\nStep1:\n",n,p)
    v1 := md5.Sum(Krand(64,3))
    v1s := fmt.Sprintf("%x",v1)
    t1s := v1s + n + p + salt
    t1h := sha1.Sum([]byte(t1s))
    t1hs := fmt.Sprintf("%x",t1h)
    h1 := v1s + t1hs
    t1s = "" //重要内容隐去 如需调试注释本行
    fmt.Printf("V1s: %s\nT1s: %s\nT1hs: %s\nCalc: %s\n\nStep2:\nsrcH: %s\n",v1s,t1s,t1hs,h1,h1)
    v2s := SubString(h1,0,32)
    t2s := v2s + n + p + salt
    t2h := sha1.Sum([]byte(t2s))
    t2hs := fmt.Sprintf("%x",t2h)
    h2 := v1s + t1hs
    t2s = "" //重要内容隐去 如需调试注释本行
    fmt.Printf("V2s: %s\nT2s: %s\nT2hs: %s\nCalc: %s\n\n",v2s,t2s,t2hs,h2)
    h3 := G(n,p)
    fmt.Printf("Step3:\nH1: %s\nV: %t",h3,V(n,p,h3))
    os.Exit(0)
}

func SubString(str string, begin, end int) string {
    rs := []rune(str)
    length := len(rs)
    if begin < 0 {
        begin = 0
    }
    if begin >= length {
        return ""
    }
    if end > length {
        return string(rs[begin:])
    }
    return string(rs[begin:end])
}