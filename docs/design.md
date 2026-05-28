# Design

`beap` redirects TCP connections created by a selected process to a SOCKS5 proxy through a local transparent proxy entrypoint. The current implementation uses cgroup eBPF to mark new TCP sockets from the target process, then uses Linux policy routing and TPROXY to deliver the marked traffic to the Go relay.

## High Level Flow

```text
target process
  |
  | connect(2)
  v
cgroup eBPF connect4/connect6
  |
  | bpf_setsockopt(SO_MARK = mark)
  v
kernel routing policy
  |
  | ip rule fwmark -> local route table
  v
iptables mangle PREROUTING TPROXY
  |
  | deliver to local transparent listener
  v
beap Go relay
  |
  | SOCKS5 CONNECT original_dst
  v
SOCKS5 proxy
```

## Process Selection

Process selection is implemented with cgroup v2 instead of PID checks inside a global hook.

In command mode, `beap` creates a temporary cgroup and starts the user command through a small shell bootstrap. The bootstrap writes its own PID to `cgroup.procs` before calling `exec` on the target command. This makes the target command run inside the selected cgroup from the beginning of `exec`, so its new connections hit the eBPF hooks.

In existing-process mode, `beap -pid <pid>` writes that PID to the selected cgroup. This only affects sockets created after the process is moved. Existing TCP connections keep their current route.

## eBPF Hook

`ebpf.go` loads two `CGroupSockAddr` programs:

- `AttachCGroupInet4Connect`
- `AttachCGroupInet6Connect`

The programs run on the `connect(2)` path and check whether `struct bpf_sock_addr.protocol` is TCP. For TCP sockets, they call `bpf_setsockopt(ctx, SOL_SOCKET, SO_MARK, &mark, 4)` to set the fwmark, then return `1` to allow the connection.

The hook does not rewrite the destination address. The original destination stays intact, and routing plus TPROXY decide whether the connection is delivered to the local transparent listener.

## Routing and TPROXY

`routing.go` installs three kinds of rules:

```sh
ip rule add fwmark <mark> table <table>
ip route replace local 0.0.0.0/0 dev lo table <table>
ip -6 route replace local ::/0 dev lo table <table>
```

These rules make marked packets use the selected routing table and resolve arbitrary destinations as local delivery.

It then inserts a mangle-table TPROXY rule:

```sh
iptables -t mangle -A PREROUTING \
  -p tcp -m mark --mark <mark>/0xffffffff \
  -j TPROXY --on-port <listen-port> --tproxy-mark <mark>/0xffffffff
```

The IPv6 `ip6tables` rule is attempted as well. If the system has no IPv6 support or no `ip6tables` command, the current implementation treats that as an optional failure and continues serving IPv4.

## Transparent Listener

`tproxy.go` creates a TCP listener with:

- `IP_TRANSPARENT`
- `IPV6_TRANSPARENT`; IPv6 setup errors are ignored

The default listener address is `:15080`. Binding to `:port` instead of `127.0.0.1:port` avoids address restrictions when TPROXY delivers traffic locally.

For every accepted connection, the relay reads the original destination. The IPv4 path uses `getsockopt(SOL_IP, SO_ORIGINAL_DST)`. If that fails, the code falls back to the connection's local address, which is useful for some transparent-proxy paths but is not reliable across all kernel and rule combinations.

## SOCKS5 Relay

`socks5.go` implements a minimal SOCKS5 client:

- no-auth method only
- `CONNECT` command only
- IPv4, IPv6, and domain-name target formats

After the relay obtains the original destination, it sends a SOCKS5 CONNECT request to the configured proxy and then forwards bytes in both directions with `io.Copy`.

## Cleanup

On normal exit, `beap` closes eBPF links, closes the listener, removes its temporary cgroup, and removes the inserted `ip rule`, `ip route`, `iptables`, and `ip6tables` rules in reverse order.

If the process is killed with `SIGKILL` or the machine stops before cleanup completes, stale rules may remain. They must be removed manually by matching the configured `mark`, `table`, and listener port.

## Design Tradeoffs

Using cgroup as the selection boundary avoids maintaining PID lists inside eBPF and naturally covers child processes forked by the target process. The tradeoff is that moving an existing process into the cgroup only affects newly created connections.

Using `SO_MARK + policy routing + TPROXY` preserves the original destination address and avoids rewriting `user_ip` or `user_port` in the eBPF program. This lets the Go relay issue the SOCKS5 CONNECT request using the real target address.

The current eBPF programs are built directly with `cilium/ebpf/asm`, avoiding a clang, bpftool, or `bpf2go` generation pipeline. The tradeoff is that the eBPF code is less readable than C source and requires care around `bpf_sock_addr` field offsets.

## Limitations

- TCP only; UDP is not handled.
- SOCKS5 supports no-auth only; username/password authentication is not implemented.
- `-pid` mode does not affect existing connections.
- Root or equivalent capabilities are required.
- cgroup v2, TPROXY, `ip`, and `iptables` are required.
- IPv6 support is best effort; missing IPv6 or `ip6tables` does not prevent IPv4 from working.
- The implementation is mainly intended for traffic originated on the local host, not for acting as a gateway proxy for other machines.
