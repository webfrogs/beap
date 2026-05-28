# eBPF Original Destination

This document describes the C eBPF implementation in `hook/kern/tproxy.c`. It redirects selected IPv4 TCP connects to the local proxy and emulates `getsockopt(SOL_IP, SO_ORIGINAL_DST)` for the accepted proxy socket.

## Problem

`cgroup/connect4` runs on the socket created by the target process. The Go proxy later calls `getsockopt(SO_ORIGINAL_DST)` on the socket returned by `accept(2)`.

Those are different kernel sockets, so their socket cookies are different. A map keyed only by `bpf_get_socket_cookie()` cannot directly connect the `connect4` event with the proxy-side `getsockopt` event.

## Correlation Strategy

The implementation uses two stages:

1. `connect4` stores the original destination by target-process socket cookie.
2. `sockops` runs after the TCP connection is established, when the source port is known, and rewrites that temporary entry into a stable client address key.
3. `getsockopt` uses the accepted socket's peer address and port to look up the original destination.

The stable key is:

```c
struct client_addr {
  __u32 ip;
  __u32 port;
};
```

For the target process, this is `local_ip4 + local_port` after connect completes. For the proxy accepted socket, the same values are visible as `sk->dst_ip4 + sk->dst_port`.

## Maps

`map_socks` is a temporary map:

```text
socket cookie -> original_dst
```

It is populated by `cg_connect4` before the destination is rewritten.

`map_original_dst` is the query map:

```text
client source ip + client source port -> original_dst
```

It is populated by the sockops established callback and queried by `cg_getsockopt`.

## Hook Flow

```text
target process connect(2)
  |
  v
cgroup/connect4
  - save original dst by socket cookie
  - rewrite destination to 127.0.0.1:18000
  |
  v
TCP established
  |
  v
sockops ACTIVE_ESTABLISHED
  - lookup original dst by socket cookie
  - save original dst by client local ip:port
  - delete temporary cookie entry
  - enable state callback for cleanup
  |
  v
proxy accept(2)
  |
  v
proxy getsockopt(SOL_IP, SO_ORIGINAL_DST)
  |
  v
cgroup/getsockopt
  - read accepted socket peer ip:port
  - lookup original dst by peer ip:port
  - write sockaddr_in into optval
```

## Cleanup

After an entry is moved from `map_socks` to `map_original_dst`, the temporary cookie entry is deleted.

The sockops program enables `BPF_SOCK_OPS_STATE_CB_FLAG` for matched sockets. When it receives `BPF_SOCK_OPS_STATE_CB` with `BPF_TCP_CLOSE`, it deletes the `client_addr -> original_dst` entry.

## Attach Points

The object contains three programs that must all be loaded and attached:

- `cgroup/connect4` as `BPF_CGROUP_INET4_CONNECT`
- `sockops` as `BPF_CGROUP_SOCK_OPS`
- `cgroup/getsockopt` as `BPF_CGROUP_GETSOCKOPT`

If any of these is missing, the chain is incomplete. In particular, without `sockops`, `getsockopt` cannot find the original destination because it does not use the connect socket cookie.

## Limitations

- IPv4 TCP only.
- The local proxy address and port are currently hard-coded in the BPF program.
- The lookup key only uses client source IP and port. This is enough for the local loopback proxy path, but should be extended if the program is later used as a gateway proxy or for more complex network namespaces.
- If a connection closes without the state callback running, `map_original_dst` can retain stale entries until overwritten or evicted by map capacity.
