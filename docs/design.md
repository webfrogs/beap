# Design

`beap` redirects selected local IPv4 TCP connections to a SOCKS5 proxy. The
current implementation selects processes by Linux task command name, rewrites
their `connect(2)` destination to a local Go relay with cgroup eBPF, and
exposes the original destination back to the relay through an eBPF-backed
`SO_ORIGINAL_DST` path.

## High Level Flow

```text
selected local process
  |
  | connect(2) to original_dst
  v
cgroup/connect4
  |
  | save original_dst by socket cookie
  | rewrite destination to 127.0.0.1:<tproxy-port>
  v
local TCP listener in beap
  |
  | getsockopt(SOL_IP, SO_ORIGINAL_DST)
  v
cgroup/getsockopt
  |
  | return original_dst recorded by eBPF
  v
beap Go relay
  |
  | SOCKS5 CONNECT original_dst
  v
SOCKS5 proxy
```

## Process Selection

Process selection is based on `task comm`, the Linux task command name returned
by `bpf_get_current_comm()`. User space writes the configured names into the
`map_proxy_comms` eBPF map before attaching the programs.

The default name list comes from `-program-names`, whose default is `agy`.
Names are comma-separated and each name must fit in `TASK_COMM_LEN`, so the
maximum accepted process name length is 15 bytes.

The proxy process itself is excluded by TGID. On startup, user space writes its
own PID into `map_proxy_tgid`; the eBPF programs use that value to avoid
redirecting `beap`'s own SOCKS5 connection attempts.

Only new `connect(2)` calls are affected. Existing TCP connections are not
changed.

## eBPF Programs

The embedded object `hook/kern/tproxy.o` is built from
`hook/kern/tproxy.c`. `main.go` loads it with `cilium/ebpf` and attaches three
programs to `/sys/fs/cgroup`:

- `cg_connect4` as `BPF_CGROUP_INET4_CONNECT`
- `record_established` as `BPF_CGROUP_SOCK_OPS`
- `cg_getsockopt` as `BPF_CGROUP_GETSOCKOPT`

`cg_connect4` handles IPv4 TCP connects. It skips non-TCP sockets, the proxy
process, unconfigured process names, and connects already targeting
`127.0.0.1`. For matched connects, it stores the original IPv4 address and port
in `map_socks` keyed by socket cookie, then rewrites the target to
`127.0.0.1:<tproxy-port>`.

`record_established` runs from the sockops hook. Once the rewritten TCP
connection is established and the client source port is known, it moves the
record from the temporary socket-cookie key to `map_original_dst`, keyed by the
client source IPv4 address and source port. It also enables TCP state callbacks
so the map entry can be deleted when the connection closes.

`cg_getsockopt` runs when the Go relay calls
`getsockopt(SOL_IP, SO_ORIGINAL_DST)`. It only handles calls from the `beap`
process. The program reads the accepted socket's peer address and port, looks
up the matching `map_original_dst` entry, and writes a `sockaddr_in` containing
the original destination into the caller's buffer.

## User Space Relay

`tproxy.go` starts a TCP listener on `127.0.0.1:<tproxy-port>`. The listener
sets `IP_TRANSPARENT` and attempts to set `IPV6_TRANSPARENT`, although the
current eBPF redirect path is IPv4-only.

For each accepted connection, the relay:

1. calls `SO_ORIGINAL_DST` to obtain the original destination;
2. opens a TCP connection to the configured SOCKS5 proxy;
3. sends a no-auth SOCKS5 `CONNECT` request for the original destination;
4. copies bytes in both directions until one side closes.

If `SO_ORIGINAL_DST` fails, the relay falls back to a non-unspecified local
address when available. In the normal eBPF path, `cg_getsockopt` supplies the
original destination.

## Configuration

Runtime configuration currently comes from command-line flags parsed in
`config/cmd_flag.go`. The `-f` flag is present, but configuration file parsing
is not implemented yet.

Default values:

```text
tproxy port:          2089
SOCKS5 proxy:         127.0.0.1:1091
proxied process name: agy
```

## Build Artifacts

The Go binary embeds `hook/kern/tproxy.o` with `go:embed`. Rebuild the eBPF
object after changing `hook/kern/tproxy.c`:

```sh
make ebpf
```

`make ebpf` regenerates `hook/kern/bpf/vmlinux.h` from kernel BTF and compiles
the C program with `clang -target bpfel`.

## Cleanup

The eBPF programs are attached through `link.Link` values. On normal exit,
`beap` closes those links, closes the listener, and closes the loaded eBPF
collection.

No `ip rule`, route table, `iptables`, or `ip6tables` rules are installed by
the current implementation.

## Design Tradeoffs

Selecting by task command name is simple and works with a single root-cgroup
attachment, but it depends on the 15-byte `task comm` value and does not give
the same isolation boundary as a dedicated cgroup.

Rewriting `connect4` to `127.0.0.1:<tproxy-port>` avoids policy routing and
iptables setup. The tradeoff is that the program needs extra eBPF state to
emulate `SO_ORIGINAL_DST`, because the relay accepts a different socket from
the original process socket.

The eBPF implementation is C source compiled to an embedded object. This keeps
the hook logic readable, but rebuilding the object requires `clang`, `bpftool`,
and kernel BTF.

## Limitations

- IPv4 TCP only; UDP and IPv6 connect redirection are not implemented.
- SOCKS5 supports no-auth only; username/password authentication is not
  implemented.
- Process selection is based on task command name, not PID or cgroup
  membership.
- Task command names are limited to 15 bytes.
- Configuration file parsing is not implemented.
- Root or equivalent capabilities are required.
- cgroup v2 and cgroup `connect4`, `sockops`, and `getsockopt` eBPF support are
  required.
