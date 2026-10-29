package dnslog

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// Run with root on a host with writable cgroup v2:
// sudo go test ./internal/dnslog -run TestDNSLogging -v
// All hooks are attached to a temporary cgroup containing only this test process.
func TestDNSLogging(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and writable cgroup v2")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	status, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	var previous string
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "0::") {
			previous = filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(line, "0::"))
		}
	}
	if previous == "" {
		t.Fatal("cgroup v2 is required")
	}
	group := filepath.Join(previous, fmt.Sprintf("beap-dns-test-%d", os.Getpid()))
	if err := os.Mkdir(group, 0755); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(group)
	if err := os.WriteFile(filepath.Join(group, "cgroup.procs"), []byte(fmt.Sprint(os.Getpid())), 0644); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.WriteFile(filepath.Join(previous, "cgroup.procs"), []byte(fmt.Sprint(os.Getpid())), 0644); err != nil {
			t.Error(err)
		}
	}()

	spec, err := ebpf.LoadCollectionSpec("../../hook/kern/tproxy.o")
	if err != nil {
		t.Fatal(err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()

	for _, name := range []string{"cg_connect4", "record_established", "cg_getsockopt", "cg_dns_connect4", "cg_dns_sendmsg4", "cg_dns_recvmsg4", "cg_dns_getpeername4", "cg_dns_log_egress", "cg_dns_log_ingress"} {
		prog := coll.Programs[name]
		attached, err := link.AttachCgroup(link.CgroupOptions{Path: group, Attach: spec.Programs[name].AttachType, Program: prog})
		if err != nil {
			t.Fatal(err)
		}
		defer attached.Close()
	}
	events, err := ringbuf.NewReader(coll.Maps["map_dns_events"])
	if err != nil {
		t.Fatal(err)
	}
	defer events.Close()
	checkEvents := func() {
		t.Helper()
		events.SetDeadline(time.Now().Add(2 * time.Second))
		seen := [2]bool{}
		for range 2 {
			record, err := events.Read()
			if err != nil {
				t.Fatal(err)
			}
			if len(record.RawSample) != 36 {
				t.Fatalf("unexpected DNS event length %d", len(record.RawSample))
			}
			direction := binary.LittleEndian.Uint32(record.RawSample[16:20])
			if direction > 1 || seen[direction] {
				t.Fatalf("unexpected DNS direction %d", direction)
			}
			seen[direction] = true
			if binary.LittleEndian.Uint64(record.RawSample[:8]) == 0 || string(record.RawSample[8:12]) != string([]byte{127, 0, 0, 4}) || binary.BigEndian.Uint16(record.RawSample[12:14]) != 53 || binary.LittleEndian.Uint32(record.RawSample[20:24]) != 12 || binary.BigEndian.Uint16(record.RawSample[24:26]) != 0x1234 {
				t.Fatalf("unexpected DNS event %x", record.RawSample)
			}
		}
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var comm [16]byte
	if err := unix.Prctl(unix.PR_GET_NAME, uintptr(unsafe.Pointer(&comm[0])), 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := coll.Maps["map_proxy_comms"].Update(comm, uint8(1), ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	target := echoUDP(t, "127.0.0.1:0")
	var targetValue [8]byte
	copy(targetValue[:4], target.IP.To4())
	binary.BigEndian.PutUint16(targetValue[4:6], uint16(target.Port))
	if err := coll.Maps["map_dns_target"].Update(uint32(0), targetValue, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	original := &net.UDPAddr{IP: net.ParseIP("127.0.0.4"), Port: 53}

	func() {
		conn, err := net.DialUDP("udp4", nil, original)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		raw, err := conn.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var peer unix.Sockaddr
		var peerErr error
		if err := raw.Control(func(fd uintptr) { peer, peerErr = unix.Getpeername(int(fd)) }); err != nil {
			t.Fatal(err)
		}
		if peerErr != nil {
			t.Fatal(peerErr)
		}
		addr, ok := peer.(*unix.SockaddrInet4)
		if !ok || addr.Port != 53 || addr.Addr != [4]byte{127, 0, 0, 4} {
			t.Fatalf("wrong getpeername: %#v", peer)
		}
		exchange(t, conn, nil, original)
		checkEvents()
	}()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	exchange(t, conn, original, original)
	checkEvents()
	// Delayed/repeated replies must retain the original mapping.
	exchange(t, conn, original, original)
	// A second resolver on the same socket is passed through instead of replacing
	// the first resolver's mapping. A delayed first reply must still be attributed.
	alternate := echoUDP(t, "127.0.0.5:53")
	exchange(t, conn, alternate, alternate)
	exchange(t, conn, original, original)
	other := echoUDP(t, "127.0.0.1:0")
	exchange(t, conn, other, other)
	// A nonselected sending task must retain normal UDP/53 behavior.
	if err := coll.Maps["map_proxy_comms"].Update(comm, uint8(0), ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	direct, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	exchange(t, direct, alternate, alternate)
	// Zero configuration must leave DNS traffic untouched even for selected tasks.
	if err := coll.Maps["map_proxy_comms"].Update(comm, uint8(1), ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := coll.Maps["map_dns_target"].Update(uint32(0), [8]byte{}, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	exchange(t, direct, alternate, alternate)
}

func echoUDP(t *testing.T, address string) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP("udp4", mustUDPAddr(t, address))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if _, err = conn.WriteToUDP(buf[:n], addr); err != nil {
				return
			}
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr)
}

func mustUDPAddr(t *testing.T, address string) *net.UDPAddr {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

func exchange(t *testing.T, conn *net.UDPConn, destination, expected *net.UDPAddr) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// A small DNS-shaped payload. Redirection must preserve all bytes.
	payload := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	var err error
	if destination == nil {
		_, err = conn.Write(payload)
	} else {
		_, err = conn.WriteToUDP(payload, destination)
	}
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, source, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != string(payload) || source.String() != expected.String() {
		t.Fatalf("got %x from %v; expected %x from %v", buf[:n], source, payload, expected)
	}
}
