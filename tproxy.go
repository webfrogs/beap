package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const soOriginalDst = 80

type proxyServer struct {
	listenAddr string
	socksAddr  string
	ln         *net.TCPListener
}

func newProxyServer(listenAddr, socksAddr string) (*proxyServer, error) {
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
			if sockErr != nil {
				return
			}
			_ = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
		})
		if err != nil {
			return err
		}
		return sockErr
	}}
	ln, err := lc.Listen(context.Background(), "tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", listenAddr, err)
	}
	tcpLn, ok := ln.(*net.TCPListener)
	if !ok {
		_ = ln.Close()
		return nil, errors.New("listener is not TCP")
	}
	return &proxyServer{listenAddr: listenAddr, socksAddr: socksAddr, ln: tcpLn}, nil
}

func (s *proxyServer) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()
	for {
		conn, err := s.ln.AcceptTCP()
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

func (s *proxyServer) Close() error {
	if s == nil || s.ln == nil {
		return nil
	}
	return s.ln.Close()
}

func (s *proxyServer) handle(client *net.TCPConn) {
	defer func() { _ = client.Close() }()
	_ = client.SetKeepAlive(true)
	_ = client.SetKeepAlivePeriod(30 * time.Second)

	remoteAddr := client.RemoteAddr()
	localAddr := client.LocalAddr()

	dst, err := originalDst(client)
	if err != nil {
		log.Printf("tproxy request remote_addr=%s local_addr=%s original_dst_error=%v", remoteAddr, localAddr, err)
		return
	}
	log.Printf("tproxy request remote_addr=%s local_addr=%s original_dst=%s", remoteAddr, localAddr, dst)

	upstream, err := socks5Connect(s.socksAddr, dst.String())
	if err != nil {
		log.Printf("socks connect %s through %s: %v", dst, s.socksAddr, err)
		return
	}
	defer func() { _ = upstream.Close() }()

	errc := make(chan error, 2)
	go pipe(upstream, client, errc)
	go pipe(client, upstream, errc)
	<-errc
}

func pipe(dst, src *net.TCPConn, errc chan<- error) {
	_, err := io.Copy(dst, src)
	_ = dst.CloseWrite()
	_ = src.CloseRead()
	errc <- err
}

func originalDst(conn *net.TCPConn) (*net.TCPAddr, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var dst *net.TCPAddr
	var ctlErr error
	err = raw.Control(func(fd uintptr) {
		dst, ctlErr = originalDst4(int(fd))
		if ctlErr == nil {
			return
		}
		if local, ok := conn.LocalAddr().(*net.TCPAddr); ok && !local.IP.IsUnspecified() {
			dst = local
			ctlErr = nil
		}
	})
	if err != nil {
		return nil, err
	}
	if ctlErr != nil {
		return nil, ctlErr
	}
	return dst, nil
}

func originalDst4(fd int) (*net.TCPAddr, error) {
	var raw [128]byte
	size := uint32(16)
	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(unix.SOL_IP),
		uintptr(soOriginalDst),
		uintptr(unsafe.Pointer(&raw[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if errno != 0 {
		return nil, errno
	}
	if size < 8 {
		return nil, fmt.Errorf("SO_ORIGINAL_DST returned short sockaddr: %d bytes", size)
	}
	port := int(binary.BigEndian.Uint16(raw[2:4]))
	ip := net.IPv4(raw[4], raw[5], raw[6], raw[7])
	return &net.TCPAddr{IP: ip, Port: port}, nil
}
