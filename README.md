# beap

`beap` means 'Bpf Enhanced Auto Proxy' and is pronounced like "Beep": short,
sharp, and compact.

`beap` is a Linux transparent proxy helper that redirects selected local TCP
connections to a SOCKS5 proxy with cgroup eBPF and a small Go relay.

The current implementation:

- loads cgroup eBPF programs on the root cgroup
- selects processes by Linux task command name
- redirects matching IPv4 TCP `connect(2)` calls to a local transparent proxy
  listener
- records the original destination in eBPF maps
- exposes that destination to the Go relay through `SO_ORIGINAL_DST`
- connects to the original destination through a SOCKS5 proxy

## Status

This project is under active development. Configuration file parsing is not
implemented yet; the runtime values are currently defined in
`config/config.go`.

Default values:

```text
transparent proxy port: 2089
SOCKS5 proxy:           127.0.0.1:1091
```

At least one proxied process name must be provided with `--program`. Process
names are matched against `task comm`, which is limited to 15 bytes.

## Requirements

- Linux with cgroup v2 mounted at `/sys/fs/cgroup`
- root privileges, or equivalent permissions for loading and attaching eBPF
  programs
- a kernel with cgroup `connect4`, `sockops`, and `getsockopt` eBPF support
- a running no-auth SOCKS5 proxy
- Go for building the userspace relay
- `clang`, `bpftool`, and kernel BTF at `/sys/kernel/btf/vmlinux` when
  rebuilding the eBPF object

## Build

Generate the eBPF object:

```sh
make ebpf
```

Build the Linux amd64 binary:

```sh
make linux_amd64
```

The generated binary is written to:

```text
build/beap_linux_amd64
```

You can also run directly during development:

```sh
sudo go run .
```

## Usage

`beap` must run as root because it loads and attaches eBPF programs and opens a
transparent proxy listener.

Start `beap` as root:

```sh
sudo ./build/beap_linux_amd64
```

### Run with Docker

The published image is:

```text
ghcr.io/webfrogs/beap:latest
```

Run it with host networking, host cgroup access, and enough privileges for eBPF:

```sh
docker rm -f beap 2>/dev/null || true; docker run --pull=always -d \
  --name beap \
  --restart=always \
  --privileged \
  --network host \
  --pid host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  ghcr.io/webfrogs/beap:latest \
    --socks5-addr 127.0.0.1:1091 \
    --program agy \
    --program curl
```

With `--network host`, `127.0.0.1:1091` refers to a SOCKS5 proxy listening on
the host. Change `--socks5-addr` if your proxy listens on another address.
Use `--program` once for each command name to proxy. At least one `--program`
flag is required.

Then start a process whose command name is listed in `ProgramNames` in
`config/config.go`. New IPv4 TCP connections from that process will be routed
through the configured SOCKS5 proxy.

### Example: Antigravity CLI

Some CLI tools cannot route their own traffic through a proxy with environment
variables. For example, if Antigravity CLI traffic is created by a process named
`agy`, run `beap` as root and forward `agy` TCP traffic to a local SOCKS5 proxy
listening on port `1091`. Use `--program agy` to proxy the Antigravity CLI
process:

```sh
sudo beap --socks5-addr 127.0.0.1:1091 --program agy
```

Or run the same Antigravity proxy setup with Docker:

```sh
docker rm -f beap 2>/dev/null || true; docker run --pull=always -d \
  --name beap \
  --restart=always \
  --privileged \
  --network host \
  --pid host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  ghcr.io/webfrogs/beap:latest \
    --socks5-addr 127.0.0.1:1091 \
    --program agy
```

Show build version information:

```sh
./build/beap_linux_amd64 -v
```

Available flags:

```text
-tproxy-port 2089             transparent proxy listen port
-socks5-addr 192.168.110.32:1091
                               SOCKS5 proxy address
-program agy                  process name to proxy; repeat for multiple programs
-f                            reserved for a future configuration file
-v                            show build version information
```

## How It Works

1. `beap` loads the embedded `hook/kern/tproxy.o` eBPF object.
2. It writes the transparent proxy port, its own process ID, and allowed
   process names into eBPF maps.
3. It attaches eBPF programs to `/sys/fs/cgroup`.
4. For matching IPv4 TCP connections, eBPF stores the original destination and
   rewrites the connect target to `127.0.0.1:<tproxy-port>`.
5. The Go relay accepts the local connection, asks `SO_ORIGINAL_DST` for the
   original target, opens a SOCKS5 `CONNECT`, and copies bytes in both
   directions.

## Limitations

- IPv4 TCP only; UDP and IPv6 connect redirection are not implemented.
- SOCKS5 username/password authentication is not implemented.
- Process selection is based on command name, not PID or cgroup membership.
- Existing connections are not affected; only new `connect(2)` calls can be
  redirected.

## License

MIT
