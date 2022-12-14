package client

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"gopkg.in/jcmturner/gokrb5.v5/iana/errorcode"
	"gopkg.in/jcmturner/gokrb5.v5/messages"
)

// SendToKDC performs network actions to send data to the KDC.
func (cl *Client) SendToKDC(b []byte, realm string) ([]byte, error) {
	var rb []byte
	if cl.Config.LibDefaults.UDPPreferenceLimit == 1 {
		//1 means we should always use TCP
		rb, errtcp := cl.sendKDCTCP(realm, b)
		if errtcp != nil {
			if e, ok := errtcp.(messages.KRBError); ok {
				return rb, e
			}
			return rb, fmt.Errorf("communication error with KDC via TCP: %v", errtcp)
		}
		return rb, nil
	}
	if len(b) <= cl.Config.LibDefaults.UDPPreferenceLimit {
		//Try UDP first, TCP second
		rb, errudp := cl.sendKDCUDP(realm, b)
		if errudp != nil {
			if e, ok := errudp.(messages.KRBError); ok && e.ErrorCode != errorcode.KRB_ERR_RESPONSE_TOO_BIG {
				// Got a KRBError from KDC
				// If this is not a KRB_ERR_RESPONSE_TOO_BIG we will return immediately otherwise will try TCP.
				return rb, e
			}
			// Try TCP
			r, errtcp := cl.sendKDCTCP(realm, b)
			if errtcp != nil {
				if e, ok := errtcp.(messages.KRBError); ok {
					// Got a KRBError
					return r, e
				}
				return r, fmt.Errorf("failed to communicate with KDC. Attempts made with UDP (%v) and then TCP (%v)", errudp, errtcp)
			}
			rb = r
		}
		return rb, nil
	}
	//Try TCP first, UDP second
	rb, errtcp := cl.sendKDCTCP(realm, b)
	if errtcp != nil {
		if e, ok := errtcp.(messages.KRBError); ok {
			// Got a KRBError from KDC so returning and not trying UDP.
			return rb, e
		}
		rb, errudp := cl.sendKDCUDP(realm, b)
		if errudp != nil {
			if e, ok := errudp.(messages.KRBError); ok {
				// Got a KRBError
				return rb, e
			}
			return rb, fmt.Errorf("failed to communicate with KDC. Attempts made with TCP (%v) and then UDP (%v)", errtcp, errudp)
		}
	}
	return rb, nil
}

func dialKDCUDP(count int, kdcs map[int]string) (conn *net.UDPConn, err error) {
	i := 1
	for i <= count {
		udpAddr, e := net.ResolveUDPAddr("udp", kdcs[i])
		if e != nil {
			err = fmt.Errorf("error resolving KDC address: %v", e)
			return
		}
		conn, err = net.DialUDP("udp", nil, udpAddr)
		if err == nil {
			conn.SetDeadline(time.Now().Add(time.Duration(5 * time.Second)))
			return
		}
		i++
	}
	err = errors.New("error in getting a UDP connection to any of the KDCs")
	return
}

func dialKDCTCP(count int, kdcs map[int]string) (conn *net.TCPConn, err error) {
	i := 1
	for i <= count {
		tcpAddr, e := net.ResolveTCPAddr("tcp", kdcs[i])
		if e != nil {
			err = fmt.Errorf("error resolving KDC address: %v", e)
			return
		}
		conn, err = net.DialTCP("tcp", nil, tcpAddr)
		if err == nil {
			conn.SetDeadline(time.Now().Add(time.Duration(5 * time.Second)))
			return
		}
		i++
	}
	err = errors.New("error in getting a TCP connection to any of the KDCs")
	return
}

// Send the bytes to the KDC over UDP.
func (cl *Client) sendKDCUDP(realm string, b []byte) ([]byte, error) {
	var r []byte
	count, kdcs, err := cl.Config.GetKDCs(realm, false)
	if err != nil {
		return r, err
	}
	conn, err := dialKDCUDP(count, kdcs)
	if err != nil {
		return r, err
	}
	r, err = cl.sendUDP(conn, b)
	if err != nil {
		return r, err
	}
	return checkForKRBError(r)
}

func (cl *Client) sendKDCTCP(realm string, b []byte) ([]byte, error) {
	var r []byte
	count, kdcs, err := cl.Config.GetKDCs(realm, true)
	if err != nil {
		return r, err
	}
	conn, err := dialKDCTCP(count, kdcs)
	if err != nil {
		return r, err
	}
	rb, err := cl.sendTCP(conn, b)
	if err != nil {
		return r, err
	}
	return checkForKRBError(rb)
}

// Send the bytes over UDP.
func (cl *Client) sendUDP(conn *net.UDPConn, b []byte) ([]byte, error) {
	var r []byte
	defer conn.Close()
	_, err := conn.Write(b)
	if err != nil {
		return r, fmt.Errorf("error sending to (%s): %v", conn.RemoteAddr().String(), err)
	}
	udpbuf := make([]byte, 4096)
	n, _, err := conn.ReadFrom(udpbuf)
	r = udpbuf[:n]
	if err != nil {
		return r, fmt.Errorf("sending over UDP failed to %s: %v", conn.RemoteAddr().String(), err)
	}
	if len(r) < 1 {
		return r, fmt.Errorf("no response data from %s", conn.RemoteAddr().String())
	}
	return r, nil
}

// Send the bytes over TCP.
func (cl *Client) sendTCP(conn *net.TCPConn, b []byte) ([]byte, error) {
	defer conn.Close()
	var r []byte
	/*
		RFC https://tools.ietf.org/html/rfc4120#section-7.2.2
		NB: network byte order == big endian
	*/
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(len(b)))
	b = append(buf.Bytes(), b...)

	_, err := conn.Write(b)
	if err != nil {
		return r, fmt.Errorf("error sending to KDC (%s): %v", conn.RemoteAddr().String(), err)
	}

	sh := make([]byte, 4, 4)
	_, err = conn.Read(sh)
	if err != nil {
		return r, fmt.Errorf("error reading response size header: %v", err)
	}
	s := binary.BigEndian.Uint32(sh)

	rb := make([]byte, s, s)
	_, err = io.ReadFull(conn, rb)
	if err != nil {
		return r, fmt.Errorf("error reading response: %v", err)
	}
	if len(rb) < 1 {
		return r, fmt.Errorf("no response data from KDC %s", conn.RemoteAddr().String())
	}
	return rb, nil
}

func checkForKRBError(b []byte) ([]byte, error) {
	var KRBErr messages.KRBError
	if err := KRBErr.Unmarshal(b); err == nil {
		return b, KRBErr
	}
	return b, nil
}
