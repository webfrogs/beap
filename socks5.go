package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

func socks5Connect(proxyAddr, target string) (*net.TCPConn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		return nil, err
	}
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("proxy connection is not TCP")
	}
	if err := tcp.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		_ = tcp.Close()
		return nil, err
	}
	if _, err := tcp.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = tcp.Close()
		return nil, err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(tcp, reply); err != nil {
		_ = tcp.Close()
		return nil, err
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		_ = tcp.Close()
		return nil, fmt.Errorf("SOCKS5 proxy rejected no-auth method: % x", reply)
	}
	req, err := socks5Request(target)
	if err != nil {
		_ = tcp.Close()
		return nil, err
	}
	if _, err := tcp.Write(req); err != nil {
		_ = tcp.Close()
		return nil, err
	}
	if err := readSocks5ConnectReply(tcp); err != nil {
		_ = tcp.Close()
		return nil, err
	}
	_ = tcp.SetDeadline(time.Time{})
	return tcp, nil
}

func socks5Request(target string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port64, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil, err
	}
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(port64))
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("target host too long: %s", host)
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, port...)
	return req, nil
}

func readSocks5ConnectReply(r io.Reader) error {
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return err
	}
	if head[0] != 0x05 {
		return fmt.Errorf("invalid SOCKS5 reply version %d", head[0])
	}
	if head[1] != 0x00 {
		return fmt.Errorf("SOCKS5 connect failed with status 0x%02x", head[1])
	}
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4 + 2
	case 0x03:
		n := make([]byte, 1)
		if _, err := io.ReadFull(r, n); err != nil {
			return err
		}
		skip = int(n[0]) + 2
	case 0x04:
		skip = 16 + 2
	default:
		return fmt.Errorf("invalid SOCKS5 address type 0x%02x", head[3])
	}
	_, err := io.CopyN(io.Discard, r, int64(skip))
	return err
}
