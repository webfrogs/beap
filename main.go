package main

import (
	"beap/config"
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed hook/kern/tproxy.o
var tproxyObject []byte

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	tproxyPort, err := checkRuntimeRequirements()
	if err != nil {
		return err
	}

	log.Printf("tproxy port: %d", config.Data.TproxyPort)
	log.Println("socks5 server: " + config.Data.Socks5Addr)
	log.Println("proxy programs: " + strings.Join(config.Data.ProgramNames, ","))

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock limit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(tproxyObject))
	if err != nil {
		return fmt.Errorf("load tproxy.o spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load tproxy.o into kernel: %w", err)
	}
	defer coll.Close()

	if err := writeProxyTGID(coll); err != nil {
		return err
	}
	if err := writeTproxyPort(coll, tproxyPort); err != nil {
		return err
	}
	if err := writeProxyComms(coll, config.Data.ProgramNames); err != nil {
		return err
	}

	links, err := attachTproxyPrograms(coll, "/sys/fs/cgroup")
	if err != nil {
		return err
	}
	defer closeLinks(links)

	log.Printf("tproxy eBPF loaded and attached to root cgroup")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxy, err := newProxyServer(net.JoinHostPort("127.0.0.1", strconv.Itoa(int(tproxyPort))), config.Data.Socks5Addr)
	if err != nil {
		return fmt.Errorf("start tproxy service: %w", err)
	}
	defer func() {
		if err := proxy.Close(); err != nil {
			log.Printf("close tproxy service: %v", err)
		}
	}()

	serveErr := make(chan error, 1)
	go func() {
		if err := proxy.Serve(ctx); err != nil {
			select {
			case serveErr <- err:
			case <-ctx.Done():
			}
		}
	}()

	log.Printf("tproxy service listening on %s", proxy.listenAddr)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)

	select {
	case <-signals:
		cancel()
		return nil
	case err := <-serveErr:
		return fmt.Errorf("tproxy service stopped: %w", err)
	}
}

func checkRuntimeRequirements() (uint16, error) {
	if runtime.GOOS != "linux" {
		return 0, fmt.Errorf("linux is required, current OS is %s", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		return 0, fmt.Errorf("root privileges are required to load eBPF programs and enable transparent proxy sockets")
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		return 0, fmt.Errorf("cgroup v2 is required at /sys/fs/cgroup: %w", err)
	}

	if err := checkSocks5Proxy(config.Data.Socks5Addr); err != nil {
		return 0, err
	}
	return config.Data.TproxyPort, nil
}

func checkSocks5Proxy(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return fmt.Errorf("SOCKS5 proxy %s is not reachable: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return fmt.Errorf("set SOCKS5 proxy check deadline: %w", err)
	}
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fmt.Errorf("check SOCKS5 proxy %s no-auth method: %w", addr, err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("read SOCKS5 proxy %s method reply: %w", addr, err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		return fmt.Errorf("SOCKS5 proxy %s does not accept no-auth method: % x", addr, reply)
	}
	return nil
}

func writeTproxyPort(coll *ebpf.Collection, port uint16) error {
	tproxyPort, ok := coll.Maps["map_tproxy_port"]
	if !ok {
		return fmt.Errorf("missing eBPF map map_tproxy_port")
	}

	key := uint32(0)
	if err := tproxyPort.Update(key, port, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("write tproxy port %d to eBPF: %w", port, err)
	}
	return nil
}

func writeProxyTGID(coll *ebpf.Collection) error {
	proxyTGID, ok := coll.Maps["map_proxy_tgid"]
	if !ok {
		return fmt.Errorf("missing eBPF map map_proxy_tgid")
	}

	key := uint32(0)
	tgid := uint32(os.Getpid())
	if err := proxyTGID.Update(key, tgid, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("write proxy tgid %d to eBPF: %w", tgid, err)
	}
	return nil
}

func writeProxyComms(coll *ebpf.Collection, names []string) error {
	proxyComms, ok := coll.Maps["map_proxy_comms"]
	if !ok {
		return fmt.Errorf("missing eBPF map map_proxy_comms")
	}

	value := uint8(1)
	for _, name := range names {
		if len(name) > 15 {
			return fmt.Errorf("process name %q is too long for task comm, max 15 bytes", name)
		}

		var key [16]byte
		copy(key[:], name)
		if err := proxyComms.Update(key, value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("write proxy process name %q to eBPF: %w", name, err)
		}
	}
	return nil
}

func attachTproxyPrograms(coll *ebpf.Collection, cgroupPath string) ([]link.Link, error) {
	programs := []struct {
		name   string
		attach ebpf.AttachType
	}{
		{name: "cg_connect4", attach: ebpf.AttachCGroupInet4Connect},
		{name: "record_established", attach: ebpf.AttachCGroupSockOps},
		{name: "cg_getsockopt", attach: ebpf.AttachCGroupGetsockopt},
	}

	links := make([]link.Link, 0, len(programs))
	for _, program := range programs {
		prog, ok := coll.Programs[program.name]
		if !ok {
			closeLinks(links)
			return nil, fmt.Errorf("missing eBPF program %s", program.name)
		}

		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  program.attach,
			Program: prog,
		})
		if err != nil {
			closeLinks(links)
			return nil, fmt.Errorf("attach %s to %s: %w", program.name, cgroupPath, err)
		}
		links = append(links, l)
	}
	return links, nil
}

func closeLinks(links []link.Link) {
	for _, l := range links {
		if err := l.Close(); err != nil {
			log.Printf("close eBPF link: %v", err)
		}
	}
}
