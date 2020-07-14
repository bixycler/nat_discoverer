// This cmd implements RFC5780's tests:
// - 4.3.  Determining NAT Mapping Behavior
// - 4.4.  Determining NAT Filtering Behavior
package main

import (
	"flag"
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus" // for logging levels

	"github.com/pion/stun"
)

type StunServerConn struct {
	conn        net.PacketConn
	LocalAddr   net.Addr
	RemoteAddr  *net.UDPAddr
	OtherAddr   *net.UDPAddr
	messageChan chan *stun.Message
}

type StunAttributes struct {
	xorAddr    *stun.XORMappedAddress
	otherAddr  *stun.OtherAddress
	respOrigin *stun.ResponseOrigin
	mappedAddr *stun.MappedAddress
	software   *stun.Software
}

func (c *StunServerConn) Close() {
	c.conn.Close()
}

var (
	addrStrPtr = flag.String("s", "stun.voip.blackberry.com:3478", "STUN server address")
	timeoutPtr = flag.Int("t", 3, "the number of seconds to wait for STUN server's response")
	verbose    = flag.Int("v", 1, "the verbosity level")
	ojson      = flag.Bool("j", false, "output result in JSON format")
)

type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrResponseMessage   = Error("error reading from response message channel")
	ErrTimedOut          = Error("timed out waiting for response")
	ErrUnsupported       = Error("no support for NAT discovery")
	messageHeaderSize    = 20
	OpenInternet         = "endpoint independent (no NAT)"
	EndpointIndependent  = "endpoint independent"
	AddressDependent     = "address dependent"
	PortDependent        = "port dependent"
	AddressPortDependent = "address and port dependent"
	Inconclusive         = "inconclusive"
)

func main() {
	flag.Parse()
	switch *verbose {
	case 0:
		log.SetLevel(log.WarnLevel)
	case 1:
		log.SetLevel(log.InfoLevel) // default
	case 2:
		log.SetLevel(log.DebugLevel)
	case 3:
		log.SetLevel(log.TraceLevel)
	}
	if *ojson {
		log.SetLevel(log.WarnLevel)
	}

	mapt, _ := MappingTests(*addrStrPtr)
	if !*ojson {
		log.Info()
		fmt.Printf("=> NAT mapping behavior: %v\n", mapt)
	}

	log.Info()
	filtert, _ := FilteringTests(*addrStrPtr)
	if !*ojson {
		log.Info()
		fmt.Printf("=> NAT filtering behavior: %v\n", filtert)
	}

	t := Inconclusive
	if mapt == OpenInternet {
		t = "open"
	} else if mapt == EndpointIndependent {
		if filtert == EndpointIndependent {
			t = "full cone"
		} else if filtert == AddressDependent {
			t = "restricted cone"
		} else if filtert == AddressPortDependent || filtert == PortDependent {
			t = "port-restricted cone"
		}
	} else if mapt != Inconclusive {
		t = "symetric"
	}
	if !*ojson {
		log.Info()
		fmt.Printf("=> NAT type (RFC-4389): %v\n", t)
	} else {
		fmt.Printf("{\n  \"mapping\": \"%v\",\n  \"filtering\": \"%v\",\n  \"type\": \"%v\"\n}\n",
			mapt, filtert, t)
	}
}

// RFC5780: (4.3 & 4.4) The first test is common for both mapping and filtering checking
func TestI(addrStr string) (*StunServerConn, *StunAttributes, error) {
	conn, err := connect(addrStr)
	if err != nil {
		return nil, nil, err
	}

	// Test I: Regular binding request
	log.Info()
	log.Info("Mapping Test I: Regular binding request")
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	resp, err := conn.roundTrip(request, conn.RemoteAddr)
	if err != nil {
		return nil, nil, err
	}

	// Parse response message for XOR-MAPPED-ADDRESS and make sure OTHER-ADDRESS valid
	res := parse(resp)
	if res.xorAddr == nil || res.otherAddr == nil ||
		res.otherAddr.IP.String() == res.respOrigin.IP.String() ||
		res.otherAddr.Port == res.respOrigin.Port {
		log.Info("Error: NAT discovery feature not supported by this server")
		return nil, nil, ErrUnsupported
	}
	addr, err := net.ResolveUDPAddr("udp4", res.otherAddr.String())
	if err != nil {
		log.Warnf("Failed resolving OTHER-ADDRESS: %v\n", res.otherAddr)
		return nil, nil, err
	}
	conn.OtherAddr = addr
	log.Infof("Received XOR-MAPPED-ADDRESS: %v\n", res.xorAddr)

	return conn, res, nil
}

// RFC5780: 4.3.+  Determining NAT Mapping Behavior (4 types)
func MappingTests(addrStr string) (string, error) {
	// Test I: Regular binding request
	conn, res1, err := TestI(addrStr)
	if conn != nil {
		defer conn.Close()
	}
	if err != nil {
		return Inconclusive, err
	}
	// Check if there's a mapping NAT
	if res1.xorAddr.String() == conn.LocalAddr.String() {
		return OpenInternet, nil
	}

	// Test II: Send binding request to the other address but primary port
	log.Info()
	log.Info("Mapping Test II: Send binding request to the other address but primary port")
	oaddr := *conn.OtherAddr
	oaddr.Port = conn.RemoteAddr.Port
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	resp, err := conn.roundTrip(request, &oaddr)
	if err != nil {
		return Inconclusive, err
	}
	res2 := parse(resp)
	log.Infof("Received XOR-MAPPED-ADDRESS: %v\n", res2.xorAddr)

	// Test III: Send binding request to the other address and port
	log.Info()
	log.Info("Mapping Test III: Send binding request to the other address and port")
	resp, err = conn.roundTrip(request, conn.OtherAddr)
	if err != nil {
		return Inconclusive, err
	}
	res3 := parse(resp)
	log.Infof("Received XOR-MAPPED-ADDRESS: %v\n", res3.xorAddr)

	// Assert mapping behavior
	if res1.xorAddr.String() == res2.xorAddr.String() {
		if res2.xorAddr.String() == res3.xorAddr.String() {
			return EndpointIndependent, nil
		} else {
			return PortDependent, nil
		}
	} else {
		if res2.xorAddr.String() == res3.xorAddr.String() {
			return AddressPortDependent, nil
		} else {
			return AddressDependent, nil
		}
	}
}

// RFC5780: 4.4.+  Determining NAT Filtering Behavior (4 types)
func FilteringTests(addrStr string) (string, error) {
	// Test I: Regular binding request
	conn, _, err := TestI(addrStr)
	if conn != nil {
		defer conn.Close()
	}
	if err != nil {
		return Inconclusive, err
	}

	// Test II: Request to change both IP and port
	log.Info()
	log.Info("Filtering Test II: Request to change both IP and port")
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	request.Add(stun.AttrChangeRequest, []byte{0x00, 0x00, 0x00, 0x06})
	conn.Close()
	conn, err = connect(addrStr)
	if err != nil {
		return Inconclusive, err
	}
	resp, err := conn.roundTrip(request, conn.RemoteAddr)
	if err == nil {
		parse(resp) // just to print out the resp
		return EndpointIndependent, nil
	} else if err != ErrTimedOut {
		return Inconclusive, err // something else went wrong
	}

	// Test III: Request to change port only
	log.Info()
	log.Info("Filtering Test III: Request to change port only")
	request.Reset()
	request.Add(stun.AttrChangeRequest, []byte{0x00, 0x00, 0x00, 0x02})
	conn.Close()
	conn, err = connect(addrStr)
	if err != nil {
		return Inconclusive, err
	}
	resp, err = conn.roundTrip(request, conn.RemoteAddr)
	if err == nil {
		parse(resp) // just to print out the resp
		return AddressDependent, nil
	} else if err != ErrTimedOut {
		return Inconclusive, err // something else went wrong
	}


	// Test IV: Request to change IP only
	log.Info()
	log.Info("Filtering Test IV: Request to change IP only")
	request.Reset()
	request.Add(stun.AttrChangeRequest, []byte{0x00, 0x00, 0x00, 0x04})
	conn.Close()
	conn, err = connect(addrStr)
	if err != nil {
		return Inconclusive, err
	}
	resp, err = conn.roundTrip(request, conn.RemoteAddr)
	if err == nil {
		parse(resp) // just to print out the resp
		return PortDependent, nil
	} else if err == ErrTimedOut {
		return AddressPortDependent, nil
	} else {
		return Inconclusive, err // something else went wrong
	}
}

// Parse a STUN message
func parse(msg *stun.Message) *StunAttributes {
	ret := &StunAttributes{
		mappedAddr: &stun.MappedAddress{},
		xorAddr:    &stun.XORMappedAddress{},
		respOrigin: &stun.ResponseOrigin{},
		otherAddr:  &stun.OtherAddress{},
		software:   &stun.Software{},
	}
	if ret.xorAddr.GetFrom(msg) != nil {
		ret.xorAddr = nil
	}
	if ret.otherAddr.GetFrom(msg) != nil {
		ret.otherAddr = nil
	}
	if ret.respOrigin.GetFrom(msg) != nil {
		ret.respOrigin = nil
	}
	if ret.mappedAddr.GetFrom(msg) != nil {
		ret.mappedAddr = nil
	}
	if ret.software.GetFrom(msg) != nil {
		ret.software = nil
	}
	log.Debugf("%v\n", msg)
	log.Debugf("\tMAPPED-ADDRESS:     %v\n", ret.mappedAddr)
	log.Debugf("\tXOR-MAPPED-ADDRESS: %v\n", ret.xorAddr)
	log.Debugf("\tRESPONSE-ORIGIN:    %v\n", ret.respOrigin)
	log.Debugf("\tOTHER-ADDRESS:      %v\n", ret.otherAddr)
	log.Debugf("\tSOFTWARE: %v\n", ret.software)
	for _, attr := range msg.Attributes {
		switch attr.Type {
		case
			stun.AttrXORMappedAddress,
			stun.AttrOtherAddress,
			stun.AttrResponseOrigin,
			stun.AttrMappedAddress,
			stun.AttrSoftware:
			break
		default:
			log.Debugf("\t%v (l=%v)\n", attr, attr.Length)
		}
	}
	return ret
}

// Given an address string, returns a StunServerConn
func connect(addrStr string) (*StunServerConn, error) {
	log.Infof("connecting to STUN server: %s\n", addrStr)
	addr, err := net.ResolveUDPAddr("udp4", addrStr)
	if err != nil {
		log.Warnf("Error resolving address: %s\n", err.Error())
		return nil, err
	}

	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		log.Warnf("Error listening on %v for UDP: %s\n", addrStr, err.Error())
		return nil, err
	}
	log.Infof("Local address: %s\n", c.LocalAddr())
	log.Infof("Remote address: %s\n", addr.String())

	mChan := listen(c)

	return &StunServerConn{
		conn:        c,
		LocalAddr:   c.LocalAddr(),
		RemoteAddr:  addr,
		messageChan: mChan,
	}, nil
}

// Send request and wait for response or timeout
func (c *StunServerConn) roundTrip(msg *stun.Message, addr net.Addr) (*stun.Message, error) {
	_ = msg.NewTransactionID()
	log.Infof("Sending to %v: (%v bytes)\n", addr, msg.Length+messageHeaderSize)
	log.Debugf("%v\n", msg)
	for _, attr := range msg.Attributes {
		log.Debugf("\t%v (l=%v)\n", attr, attr.Length)
	}
	_, err := c.conn.WriteTo(msg.Raw, addr)
	if err != nil {
		log.Warnf("Error sending request to %v\n", addr)
		return nil, err
	}

	// Wait for response or timeout
	select {
	case m, ok := <-c.messageChan:
		if !ok {
			log.Infof("Error receiving response from server %v\n", addr)
			return nil, ErrResponseMessage
		}
		return m, nil
	case <-time.After(time.Duration(*timeoutPtr) * time.Second):
		log.Infof("Timed out waiting for response from server %v\n", addr)
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
			log.Infof("Response from %v: (%v bytes)\n", addr, n)
			buf = buf[:n]

			m := new(stun.Message)
			m.Raw = buf
			err = m.Decode()
			if err != nil {
				log.Infof("Error decoding message: %v\n", err)
				close(messages)
				return
			}

			messages <- m
		}
	}()
	return
}
