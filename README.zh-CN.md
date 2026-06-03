# beap

`beap` 是 `Bpf Enhanced Auto Proxy` 的缩写，读音类似 "Beep"，听起来短小精悍。

`beap` 是一个 Linux 透明代理辅助工具。它通过 cgroup eBPF 和一个小型 Go 转发器，把选定本地进程的 TCP 连接重定向到 SOCKS5 代理。

当前实现能力：

- 在根 cgroup 上加载 cgroup eBPF 程序
- 按 Linux 任务命令名选择需要代理的进程
- 将匹配进程的 IPv4 TCP `connect(2)` 调用重定向到本地透明代理监听端口
- 在 eBPF map 中记录原始目标地址
- 通过 `SO_ORIGINAL_DST` 将原始目标地址暴露给 Go 转发器
- 通过 SOCKS5 代理连接到原始目标地址

## 状态

项目仍在活跃开发中。配置文件解析尚未实现；运行时配置目前定义在 `config/config.go` 中。

默认值：

```text
透明代理端口:      2089
SOCKS5 代理:       127.0.0.1:1091
被代理进程名:      agy
```

进程名会和 `task comm` 匹配，而 `task comm` 最多只有 15 字节。

## 要求

- Linux，并且 cgroup v2 挂载在 `/sys/fs/cgroup`
- root 权限，或具备加载和附加 eBPF 程序的等效权限
- 内核支持 cgroup `connect4`、`sockops` 和 `getsockopt` eBPF
- 一个正在运行且不需要认证的 SOCKS5 代理
- Go，用于构建用户态转发器
- 重新构建 eBPF object 时需要 `clang`、`bpftool`，以及位于 `/sys/kernel/btf/vmlinux` 的 kernel BTF

## 构建

生成 eBPF object：

```sh
make ebpf
```

构建 Linux amd64 二进制：

```sh
make linux_amd64
```

生成的二进制文件会写入：

```text
build/beap_linux_amd64
```

开发时也可以直接运行：

```sh
sudo go run .
```

## 使用

`beap` 必须以 root 身份运行，因为它需要加载并附加 eBPF 程序，还需要打开透明代理监听端口。

以 root 身份启动 `beap`：

```sh
sudo ./build/beap_linux_amd64
```

### 使用 Docker 运行

已发布的镜像地址：

```text
ghcr.io/webfrogs/beap:latest
```

运行时需要使用 host 网络、挂载 host cgroup，并提供 eBPF 所需权限：

```sh
docker run --rm -it \
  --name beap \
  --privileged \
  --network host \
  --pid host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  ghcr.io/webfrogs/beap:latest \
    --socks5-addr 127.0.0.1:1091 \
    --program-names agy
```

使用 `--network host` 时，`127.0.0.1:1091` 指的是 host 上监听的 SOCKS5
代理。如果你的代理监听在其他地址，请修改 `--socks5-addr`。

然后启动一个命令名包含在 `config/config.go` 的 `ProgramNames` 中的进程。该进程新建的 IPv4 TCP 连接会通过配置的 SOCKS5 代理转发。

### 示例：Antigravity CLI

有些 CLI 工具无法通过环境变量代理自己的流量。例如，Antigravity CLI 的流量由名为 `agy` 的进程发起，以 root 身份运行 `beap`，并把 `agy` 的 TCP 流量转发到本地 `1091` 端口上的 SOCKS5 代理：

```sh
sudo beap --socks5-addr 127.0.0.1:1091 --program-names agy
```

也可以使用 Docker 运行同样的 Antigravity 代理配置：

```sh
docker run -d \
  --name beap \
  --privileged \
  --network host \
  --pid host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  ghcr.io/webfrogs/beap:latest \
    --socks5-addr 127.0.0.1:1091 \
    --program-names agy
```

显示构建版本信息：

```sh
./build/beap_linux_amd64 -v
```

可用参数：

```text
-tproxy-port 2089             透明代理监听端口
-socks5-addr 192.168.110.32:1091
                               SOCKS5 代理地址
-program-names agy            需要代理的进程名，多个名称用逗号分隔
-f                            预留给未来的配置文件功能
-v                            显示构建版本信息
```

## 工作原理

1. `beap` 加载嵌入的 `hook/kern/tproxy.o` eBPF object。
2. 它将透明代理端口、自身进程 ID 和允许代理的进程名写入 eBPF map。
3. 它把 eBPF 程序附加到 `/sys/fs/cgroup`。
4. 对于匹配的 IPv4 TCP 连接，eBPF 会保存原始目标地址，并把 connect 目标改写为 `127.0.0.1:<tproxy-port>`。
5. Go 转发器接收本地连接，通过 `SO_ORIGINAL_DST` 获取原始目标地址，发起 SOCKS5 `CONNECT`，然后在两个连接之间复制数据。

## 限制

- 仅支持 IPv4 TCP；尚未实现 UDP 和 IPv6 connect 重定向。
- 尚未实现 SOCKS5 用户名/密码认证。
- 进程选择基于命令名，不基于 PID 或 cgroup 成员关系。
- 已存在的连接不会受影响；只有新的 `connect(2)` 调用可以被重定向。

## License

MIT
