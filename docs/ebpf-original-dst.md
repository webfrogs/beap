# eBPF Original Destination

This document describes how `hook/kern/tproxy.c` preserves the original IPv4
TCP destination after `cgroup/connect4` rewrites a selected connection to the
local Go relay.

## Problem

`cg_connect4` runs on the socket created by the selected process. The Go relay
later calls `getsockopt(SOL_IP, SO_ORIGINAL_DST)` on the socket returned by
`accept(2)`.

Those are different kernel sockets, so their socket cookies are different. A
map keyed only by `bpf_get_socket_cookie()` cannot directly connect the
`connect4` event with the relay-side `getsockopt` event.

## Correlation Strategy

The implementation uses three stages:

1. `cg_connect4` stores the original destination by target-process socket
   cookie before rewriting the connect target.
2. `record_established` runs after the rewritten TCP connection is established,
   when the client's source port is known, and moves that temporary entry to a
   stable client address key.
3. `cg_getsockopt` uses the accepted socket's peer address and peer port to
   look up the original destination.

The stable key is:

```c
struct client_addr {
  __u32 ip;
  __u32 port;
};
```

For the selected process, this key is `local_ip4 + local_port` from the
established client socket. For the relay's accepted socket, the same values are
visible as `sk->dst_ip4 + ntohs(sk->dst_port)`.

## Maps

`map_tproxy_port` is an array map written by user space:

```text
key 0 -> transparent proxy listen port
```

`map_proxy_tgid` is an array map written by user space:

```text
key 0 -> beap process TGID/PID
```

It lets eBPF avoid redirecting the relay's own upstream SOCKS5 connections.

`map_proxy_comms` is a hash map of allowed process names:

```text
task comm -> enabled flag
```

`map_socks` is the temporary original-destination map:

```text
socket cookie -> original_dst
```

It is populated by `cg_connect4` before the destination is rewritten.

`map_original_dst` is the relay query map:

```text
client source ip + client source port -> original_dst
```

It is populated by `record_established` and queried by `cg_getsockopt`.

## Hook Flow

```text
selected process connect(2)
  |
  v
cgroup/connect4
  - skip non-TCP sockets
  - skip the beap process
  - skip process names not present in map_proxy_comms
  - skip destinations already at 127.0.0.1
  - save original dst by socket cookie
  - rewrite destination to 127.0.0.1:<map_tproxy_port>
  |
  v
TCP established
  |
  v
sockops ACTIVE_ESTABLISHED
  - lookup original dst by socket cookie
  - save original dst by client local ip:port
  - delete temporary cookie entry
  - enable TCP state callback for cleanup
  |
  v
beap accepts local connection
  |
  v
beap getsockopt(SOL_IP, SO_ORIGINAL_DST)
  |
  v
cgroup/getsockopt
  - verify caller is the beap process
  - read accepted socket peer ip:port
  - lookup original dst by peer ip:port
  - write sockaddr_in into optval
```

## Cleanup

After an entry is moved from `map_socks` to `map_original_dst`, the temporary
cookie entry is deleted.

The sockops program enables `BPF_SOCK_OPS_STATE_CB_FLAG` for matched sockets.
When it receives `BPF_SOCK_OPS_STATE_CB` with `BPF_TCP_CLOSE`, it deletes the
`client_addr -> original_dst` entry.

If the process exits before a connection reaches `ACTIVE_ESTABLISHED`, the
temporary `map_socks` entry may remain until overwritten or evicted by map
capacity.

## Attach Points

The object contains three programs that must all be loaded and attached:

- `cg_connect4` as `BPF_CGROUP_INET4_CONNECT`
- `record_established` as `BPF_CGROUP_SOCK_OPS`
- `cg_getsockopt` as `BPF_CGROUP_GETSOCKOPT`

If any of these is missing, the chain is incomplete. In particular, without
`record_established`, `cg_getsockopt` cannot find the original destination
because it does not use the connect socket cookie.

## Limitations

- IPv4 TCP only.
- The local proxy address is fixed to `127.0.0.1`; the local proxy port is
  supplied through `map_tproxy_port`.
- Process matching uses `task comm`, which is limited to 15 bytes.
- The lookup key only uses client source IP and port. This is enough for the
  local loopback relay path, but should be extended if the program is later
  used as a gateway proxy or for more complex network namespaces.
- If a connection closes without the state callback running, `map_original_dst`
  can retain stale entries until overwritten or evicted by map capacity.
