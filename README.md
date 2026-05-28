# beap

`beap` redirects TCP connections created by a selected process to a SOCKS5 proxy by combining:

- cgroup eBPF `connect4/connect6` hooks to set `SO_MARK` on new TCP sockets
- Linux policy routing to route marked packets back to local delivery
- iptables/ip6tables `TPROXY` to deliver the traffic to a transparent local listener
- a Go TCP relay that connects to the original destination through SOCKS5

## Requirements

- Linux with cgroup v2 mounted at `/sys/fs/cgroup`
- root privileges or equivalent `CAP_BPF` and `CAP_NET_ADMIN`
- `ip`, `iptables`, and the `TPROXY` target available
- a running SOCKS5 proxy

## Usage

Run a command under interception:

```sh
sudo go run . -socks 127.0.0.1:1080 -- curl https://example.com
```

Move an existing process into the interception cgroup:

```sh
sudo go run . -pid 1234 -socks 127.0.0.1:1080
```

Only new TCP connections are affected. Existing connections keep their current route.

Useful flags:

```text
-listen :15080             transparent listener address
-mark 0x1eed              fwmark used by eBPF and TPROXY
-table 100                policy routing table id
-cleanup-net=true         remove inserted route/rule/iptables entries on exit
```

## Notes

The program cleans up the rules it inserts when it exits normally. If it is killed with `SIGKILL`, remove stale entries manually with matching `ip rule`, `ip route`, `iptables -t mangle`, and `ip6tables -t mangle` commands.
