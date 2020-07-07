// This cmd implements RFC5780's tests:
// - 4.3.  Determining NAT Mapping Behavior
// - 4.4.  Determining NAT Filtering Behavior
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"time"

	"github.com/bixycler/stun"
)

type StunServerConn struct {
	conn        net.PacketConn
	LocalAddr   net.Addr
	RemoteAddr  *net.UDPAddr
	OtherAddr   *net.UDPAddr
	messageChan chan *stun.Message
}

func (c *StunServerConn) Close() {
	c.conn.Close()
}

var (
	addrStrPtr  = flag.String("server", "stun.voip.blackberry.com:3478", "STUN server address")
	timeoutPtr  = flag.Int("timeout", 3, "the number of seconds to wait for STUN server's response")
	ErrTimedOut = errors.New("Timed out waiting for response")
	verbose     = flag.Int("verbose", 1, "the verbosity level")
	ErrNoOtherAddress = errors.New("No OTHER-ADDRESS in message")
)

func main() {
	flag.Parse()

	if err := MappingTests(*addrStrPtr); err != nil {
		fmt.Println("NAT mapping behavior: inconclusive")
	}
	if err := FilteringTests(*addrStrPtr); err != nil {
		fmt.Println("NAT filtering behavior: inconclusive")
	}
}

// RFC5780: 4.3.  Determining NAT Mapping Behavior
func MappingTests(addrStr string) error {
	var xorAddr1, xorAddr2, xorAddr3   *stun.XORMappedAddress
	var otherAddr *stun.OtherAddress

	mapTestConn, err := connect(addrStr)
	if err != nil {
		if *verbose >=1 { fmt.Printf("Error creating STUN connection: %s\n", err.Error()) }
		return err
	}
	defer mapTestConn.Close()

	// Test I: Regular binding request
	if *verbose >=1 { fmt.Println("\nMapping Test I: Regular binding request") }
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	resp, err := mapTestConn.roundTrip(request, mapTestConn.RemoteAddr)
	if err != nil {
		return err
	}

	// Parse response message for XOR-MAPPED-ADDRESS and make sure OTHER-ADDRESS valid
	xorAddr1, otherAddr, _,_,_ = parse(resp)
	if xorAddr1 == nil || otherAddr == nil {
		fmt.Println("Error: NAT discovery feature not supported by this server")
		return ErrNoOtherAddress
	}
	addr, err := net.ResolveUDPAddr("udp4", otherAddr.String())
	if err != nil {
		if *verbose >=1 { fmt.Printf("Failed resolving OTHER-ADDRESS: %v\n", otherAddr) }
		return err
	}
	mapTestConn.OtherAddr = addr
	if *verbose >=1 { fmt.Printf("Received XOR-MAPPED-ADDRESS: %v\n", xorAddr1) }

	// Assert mapping behavior
	if xorAddr1.String() == mapTestConn.LocalAddr.String() {
		fmt.Println("\n=> NAT mapping behavior: endpoint independent (no NAT)")
		return nil
	}

	// Test II: Send binding request to the other address but primary port
	if *verbose >=1 { fmt.Println("\nMapping Test II: Send binding request to the other address but primary port") }
	oaddr := *mapTestConn.OtherAddr
	oaddr.Port = mapTestConn.RemoteAddr.Port
	resp, err = mapTestConn.roundTrip(request, &oaddr)
	if err != nil {
		return err
	}

	// Assert mapping behavior
	xorAddr2, otherAddr, _,_,_ = parse(resp)
	if *verbose >=1 { fmt.Printf("Received XOR-MAPPED-ADDRESS: %v\n", xorAddr2) }
	if xorAddr1.String() == xorAddr2.String() {
		fmt.Println("\n=> NAT mapping behavior: endpoint independent")
		return nil
	}

	// Test III: Send binding request to the other address and port
	if *verbose >=1 { fmt.Println("\nMapping Test III: Send binding request to the other address and port") }
	resp, err = mapTestConn.roundTrip(request, mapTestConn.OtherAddr)
	if err != nil {
		return err
	}

	// Assert mapping behavior
	xorAddr3, otherAddr, _,_,_ = parse(resp)
	if *verbose >=1 { fmt.Printf("Received XOR-MAPPED-ADDRESS: %v\n", xorAddr3) }
	if xorAddr3.String() == xorAddr2.String() {
		fmt.Println("\n=> NAT mapping behavior: address dependent")
		return nil
	} else {
		fmt.Println("\n=> NAT mapping behavior: address and port dependent")
		return nil
	}

	return nil
}

// RFC5780: 4.4.  Determining NAT Filtering Behavior
func FilteringTests(addrStr string) error {
	var xorAddr *stun.XORMappedAddress
	var otherAddr *stun.OtherAddress

	mapTestConn, err := connect(addrStr)
	if err != nil {
		if *verbose >=1 { fmt.Printf("Error creating STUN connection: %s\n", err.Error()) }
		return err
	}
	defer mapTestConn.Close()

	// Test I: Regular binding request
	if *verbose >=1 { fmt.Println("\nFiltering Test I: Regular binding request") }
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	resp, err := mapTestConn.roundTrip(request, mapTestConn.RemoteAddr)
	if err != nil || err == ErrTimedOut {
		return err
	}
	xorAddr, otherAddr, _,_,_ = parse(resp)
	if xorAddr == nil || otherAddr == nil {
		fmt.Println("Error: NAT discovery feature not supported by this server")
		return ErrNoOtherAddress
	}
	addr, err := net.ResolveUDPAddr("udp4", otherAddr.String())
	if err != nil {
		if *verbose >=1 { fmt.Printf("Failed resolving OTHER-ADDRESS: %v\n", otherAddr) }
		return err
	}
	mapTestConn.OtherAddr = addr

	// Test II: Request to change both IP and port
	if *verbose >=1 { fmt.Println("\nFiltering Test II: Request to change both IP and port") }
	request.Reset(); request.Add(stun.AttrChangeRequest, []byte{0x00, 0x00, 0x00, 0x06})

	resp, err = mapTestConn.roundTrip(request, mapTestConn.RemoteAddr)
	if err == nil {
		parse(resp)
		fmt.Println("\n=> NAT filtering behavior: endpoint independent")
		return nil
	} else if err != ErrTimedOut {
		return err // something else went wrong
	}

	// Test III: Request to change port only
	if *verbose >=1 { fmt.Println("\nFiltering Test III: Request to change port only") }
	request.Reset(); request.Add(stun.AttrChangeRequest, []byte{0x00, 0x00, 0x00, 0x02})

	resp, err = mapTestConn.roundTrip(request, mapTestConn.RemoteAddr)
	if err == nil {
		parse(resp)
		fmt.Println("\n=> NAT filtering behavior: address dependent")
	} else if err == ErrTimedOut {
		fmt.Println("\n=> NAT filtering behavior: address and port dependent")
	} else {
		return err // something else went wrong
	}

	return nil
}

// Parse a STUN message
func parse(msg *stun.Message) (
	xorAddr     *stun.XORMappedAddress,
	otherAddr   *stun.OtherAddress,
	respOrigin  *stun.ResponseOrigin,
	mappedAddr  *stun.MappedAddress,
	software    *stun.Software,
) {
	xorAddr     = &stun.XORMappedAddress{}
	otherAddr   = &stun.OtherAddress{}
	respOrigin  = &stun.ResponseOrigin{}
	mappedAddr  = &stun.MappedAddress{}
	software    = &stun.Software{}
	if xorAddr.GetFrom(msg) != nil { xorAddr = nil }
	if otherAddr.GetFrom(msg) != nil { otherAddr = nil }
	if respOrigin.GetFrom(msg) != nil { respOrigin = nil }
	if mappedAddr.GetFrom(msg) != nil { mappedAddr = nil }
	if software.GetFrom(msg) != nil { software = nil }
	if *verbose >= 2 {
		fmt.Printf("%v\n", msg);
		fmt.Printf("\tMAPPED-ADDRESS:     %v\n", mappedAddr)
		fmt.Printf("\tXOR-MAPPED-ADDRESS: %v\n", xorAddr);
		fmt.Printf("\tRESPONSE-ORIGIN:    %v\n", respOrigin)
		fmt.Printf("\tOTHER-ADDRESS:      %v\n", otherAddr)
		fmt.Printf("\tSOFTWARE: %v\n", software)
		for _, attr := range msg.Attributes {
			switch attr.Type {
				case
				stun.AttrXORMappedAddress,
				stun.AttrOtherAddress,
				stun.AttrResponseOrigin,
				stun.AttrMappedAddress,
				stun.AttrSoftware: break
				default: fmt.Printf("\t%v (l=%v)\n", attr, attr.Length)
			}
		}
	}
	return
}

// Given an address string, returns a StunServerConn
func connect(addrStr string) (*StunServerConn, error) {
	if *verbose >=1 { fmt.Printf("\nconnecting to STUN server: %s\n", addrStr) }
	addr, err := net.ResolveUDPAddr("udp4", addrStr)
	if err != nil {
		if *verbose >=1 { fmt.Printf("Error resolving address: %s\n", err.Error()) }
		return nil, err
	}

	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, err
	}
	if *verbose >=1 { fmt.Printf("Local address: %s\n", c.LocalAddr()) }
	if *verbose >=1 { fmt.Printf("Remote address: %s\n", addr.String()) }

	mChan := listen(c)

	return &StunServerConn{
		conn        :c,
		LocalAddr   :c.LocalAddr(),
		RemoteAddr  :addr,
		messageChan :mChan,
	}, nil
}

// Send request and wait for response or timeout
func (c *StunServerConn) roundTrip(msg *stun.Message, addr net.Addr) (*stun.Message, error) {
	if *verbose >=1 { fmt.Printf("Sending to %v: (%v bytes)\n", addr, msg.Length + 20) }
	if *verbose >=2 {
		fmt.Printf("%v\n", msg);
        for _, attr := range msg.Attributes {
            fmt.Printf("\t%v (l=%v)\n", attr, attr.Length)
        }
    }
    msg.NewTransactionID()
	_, err := c.conn.WriteTo(msg.Raw, addr)
	if err != nil {
		if *verbose >=1 {
			fmt.Printf("Error sending request to %v\n", addr)
		}
		return nil, err
	}

	// Wait for response or timeout
	select {
	case m, ok := <-c.messageChan:
		if !ok {
			return nil, fmt.Errorf("error reading from messageChan")
		}
		return m, nil
	case <-time.After(time.Duration(*timeoutPtr) * time.Second):
		if *verbose >=1 {
			fmt.Printf("Timed out waiting for response from server %v\n", addr)
		}
		return nil, ErrTimedOut
	}
}


// taken from https://github.com/pion/stun/blob/master/cmd/stun-traversal/main.go
func listen(conn *net.UDPConn) (messages chan *stun.Message) {
	messages = make(chan *stun.Message)
	go func() {
		for {
			buf := make([]byte, 1024)

			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				close(messages)
				return
			}
			if *verbose >=1 { fmt.Printf("Response from %v: (%v bytes)\n", addr, n) }
			buf = buf[:n]

			m := new(stun.Message)
			m.Raw = buf
			err = m.Decode()
			if err != nil {
				if *verbose >=1 { fmt.Printf("Error decoding message: %v\n", err) }
				close(messages)
				return
			}

			messages <- m
		}
	}()
	return
}
