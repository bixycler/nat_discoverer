package main

/*
  Ref: github.com/songjiayang/natat
*/

import (
    "flag"
    "fmt"
    "log"
    "net"
//    "strings"
    "os"

    //"gortc.io/stun"
    //"github.com/pion/stun" //Pion's STUN is ported from gortc.io/stun
    "github.com/bixycler/stun" //to be merged into pion/stun
)

type BindingResponse struct {
    XORMapped   *stun.XORMappedAddress
    Mapped      *stun.MappedAddress
    Origin      *stun.ResponseOrigin
    Source      *stun.MappedAddress
    Other       *stun.OtherAddress
    Changed     *stun.MappedAddress
    Software    *stun.Software
}

var (
    bindAddrStr = flag.String("bind", "0.0.0.0:0", "The local binding address (default = autobind)")
    addrShowing = flag.Bool("addr", true, "Whether to show server's address(es)")
    debugLev = flag.Int("debug", 0, "The debugging level")
    stunAddrStr string
)

func main() {
    flag.Parse()
    stunAddrStr = flag.Arg(0)
    if len(stunAddrStr)==0 {
        fmt.Fprintf(os.Stderr, "%s [options] STUN_ADDR:PORT\nOptions:\n", os.Args[0])
        flag.PrintDefaults();
        return
    }

    // resolve UDP address
    bindAddr := resolveUDPAddr(*bindAddrStr)
    stunAddr := resolveUDPAddr(stunAddrStr)

    fmt.Printf("%v\t%v\t",stunAddr,stunAddrStr,)
    res := stunMustRequest(bindAddr, stunAddr)
    if res.XORMapped != nil { fmt.Printf("XMap") }
    fmt.Printf("\t")
    if res.Mapped != nil { fmt.Printf("Map") }
    fmt.Printf("\t")
    if res.Origin != nil { fmt.Printf("Orig"); if *addrShowing==true { fmt.Printf(":%v",res.Origin) } }
    fmt.Printf("\t")
    if res.Source != nil { fmt.Printf("Src"); if *addrShowing==true { fmt.Printf(":%v",res.Source) } }
    fmt.Printf("\t")
    if res.Other != nil { fmt.Printf("Oth"); if *addrShowing==true { fmt.Printf(":%v",res.Other) } }
    fmt.Printf("\t")
    if res.Changed != nil { fmt.Printf("Chg"); if *addrShowing==true { fmt.Printf(":%v",res.Changed) } }
    fmt.Printf("\t")
    if res.Software != nil { fmt.Printf("Software:\"%v\"",res.Software) }
    fmt.Printf("\n")
}

func stunRequest(bindAddr, stunAddr *net.UDPAddr) (res BindingResponse, err error) {
    // use DialUDP() for setting local (bind) address, which is unsupported by Dial()
    conn, err := net.DialUDP("udp", bindAddr, stunAddr)
    client, err := stun.NewClient(conn); defer client.Close()
    if err != nil { return }

    // send the binding request and receive response from STUN server
    reqmsg := stun.MustBuild(stun.TransactionID, stun.BindingRequest);
    resmsg := stun.New()
    err = client.Do(reqmsg, func(res stun.Event) {
        if res.Error != nil { log.Printf("%v\n",res.Error); return }
        res.Message.CloneTo(resmsg) //(from godoc:) Do not reuse event outside Handler.
        //*DEBUG*/log.Printf("%v TransactionID=%v\n",stunAddr,res.TransactionID)
    });
    if err != nil { return }
    //*DEBUG*/log.Printf("%v TransactionID=%v\n",stunAddr,resmsg.TransactionID)
    if *debugLev > 0 {
        fmt.Printf("Attr+{");
        for _,attr := range resmsg.Attributes {
            switch attr.Type {
                case
                stun.AttrXORMappedAddress,
                stun.AttrSourceAddress,
                stun.AttrResponseOrigin,
                stun.AttrChangedAddress,
                stun.AttrOtherAddress,
                stun.AttrMappedAddress,
                stun.AttrSoftware: break
                default: fmt.Printf("%v ",attr.Type)
            }
        }; fmt.Printf("}\t")

    }
    if *debugLev > 1 { fmt.Println(); for _,attr := range resmsg.Attributes {
        fmt.Printf("\t%v (l=%v)\n", attr,attr.Length)
    }}

    // parse the response
    res = BindingResponse{
        XORMapped:  &stun.XORMappedAddress{},
        Mapped:     &stun.MappedAddress{},
        Origin:     &stun.ResponseOrigin{},
        Source:     &stun.MappedAddress{},
        Other:      &stun.OtherAddress{},
        Changed:    &stun.MappedAddress{},
        Software:   &stun.Software{},
    }
    if res.XORMapped.GetFrom(resmsg) != nil { res.XORMapped = nil }
    if res.Mapped.GetFrom(resmsg) != nil { res.Mapped = nil }
    if res.Origin.GetFrom(resmsg) != nil { res.Origin = nil }
    if res.Source.GetFromAs(resmsg,stun.AttrSourceAddress) != nil { res.Source = nil }
    if res.Other.GetFrom(resmsg) != nil { res.Other = nil }
    if res.Changed.GetFromAs(resmsg,stun.AttrChangedAddress) != nil { res.Changed = nil }
    if res.Software.GetFrom(resmsg) != nil { res.Software = nil }

    return
}

func stunMustRequest(bindAddr, stunAddr *net.UDPAddr) (res BindingResponse) {
    res,err := stunRequest(bindAddr, stunAddr)
    if err != nil {
        log.Panicf("stunRequest(%v -> %v) error: %v", bindAddr, stunAddr, err)
    }
    return
}

/*func namedAttr(s string) string {
    for id,name := range AttrTypeString {
        s = strings.Replace(s, fmt.Sprintf("%#x:",uint(id)), name+":", 1)
    }
    return s
}*/

func resolveUDPAddr(addrStr string) *net.UDPAddr {
    addr, err := net.ResolveUDPAddr("udp", addrStr)
    if err != nil {
        log.Panicf("\"%v\" resolution failed: %v", addrStr, err)
    }
    return addr
}
