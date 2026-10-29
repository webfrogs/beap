#include "bpf/vmlinux.h"
#include "bpf/bpf_endian.h"
#include "bpf/bpf_helpers.h"

#define SOL_IP 0
#define SO_ORIGINAL_DST 80
#define AF_INET 2
#define EINVAL 22
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define TASK_COMM_LEN 16

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

struct process_comm {
  char name[TASK_COMM_LEN];
};

struct original_dst {
  __u32 ip;
  __u32 port;
};

struct client_addr {
  __u32 ip;
  __u32 port;
};

// Network byte order, matching bpf_sock_addr fields. Port zero disables DNS.
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct original_dst);
  __uint(max_entries, 1);
} map_dns_target SEC(".maps");

// Socket storage is reclaimed automatically when the socket is destroyed.
// Pin one original DNS endpoint per socket: overwriting it would misattribute
// delayed replies when sendto() addresses multiple resolvers on one socket.
struct {
  __uint(type, BPF_MAP_TYPE_SK_STORAGE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, int);
  __type(value, struct original_dst);
} map_dns_original SEC(".maps");

// 用户态写入当前透明代理监听端口。
// key 0 -> tproxy port
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u16);
  __uint(max_entries, 1);
} map_tproxy_port SEC(".maps");

// 用户态加载程序后写入当前代理进程的 TGID/PID。
// key 0 -> proxy tgid
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, 1);
} map_proxy_tgid SEC(".maps");

// 用户态写入允许代理的程序名列表，key 为 task comm。
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct process_comm);
  __type(value, __u8);
  __uint(max_entries, 64);
} map_proxy_comms SEC(".maps");

// connect4 阶段先用 socket cookie 暂存原始目标地址。
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u64);
  __type(value, struct original_dst);
  __uint(max_entries, 1024);
} map_socks SEC(".maps");

// TCP 建立后用客户端源地址和源端口关联原始目标地址，供代理侧 getsockopt 查询。
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct client_addr);
  __type(value, struct original_dst);
  __uint(max_entries, 1024);
} map_original_dst SEC(".maps");

static __always_inline bool is_proxy_process(void) {
  __u32 key = 0;
  __u32 *proxy_tgid = bpf_map_lookup_elem(&map_proxy_tgid, &key);
  if (!proxy_tgid || *proxy_tgid == 0) {
    return false;
  }

  __u32 current_tgid = bpf_get_current_pid_tgid() >> 32;
  return current_tgid == *proxy_tgid;
}

static __always_inline bool is_allowed_process(void) {
  struct process_comm comm = {};
  if (bpf_get_current_comm(&comm.name, sizeof(comm.name)) != 0) {
    return false;
  }

  __u8 *enabled = bpf_map_lookup_elem(&map_proxy_comms, &comm);
  return enabled && *enabled != 0;
}

static __always_inline __u16 get_tproxy_port(void) {
  __u32 key = 0;
  __u16 *port = bpf_map_lookup_elem(&map_tproxy_port, &key);
  if (!port) {
    return 0;
  }
  return *port;
}

static __always_inline int redirect_dns(struct bpf_sock_addr *ctx) {
  if (!ctx->sk || ctx->user_port != bpf_htons(53) ||
      is_proxy_process() || !is_allowed_process()) {
    return 1;
  }
  __u32 key = 0;
  struct original_dst *target = bpf_map_lookup_elem(&map_dns_target, &key);
  if (!target || !target->port) {
    return 1;
  }
  // No translation is necessary when the requested endpoint is already target.
  if (ctx->user_ip4 == target->ip && ctx->user_port == target->port) {
    return 1;
  }
  struct original_dst initial = {
      .ip = ctx->user_ip4, .port = ctx->user_port,
  };
  struct original_dst *original = bpf_sk_storage_get(
      &map_dns_original, ctx->sk, &initial, BPF_SK_STORAGE_GET_F_CREATE);
  if (!original || original->ip != ctx->user_ip4 ||
      original->port != ctx->user_port) {
    return 1;
  }
  ctx->user_ip4 = target->ip;
  ctx->user_port = target->port;
  return 1;
}

// Receive hooks run in the receiving task, which need not be the sending task.
// Use socket storage rather than comm to identify replies that need restoring.
static __always_inline int restore_dns(struct bpf_sock_addr *ctx) {
  if (!ctx->sk || ctx->protocol != IPPROTO_UDP) {
    return 1;
  }
  __u32 key = 0;
  struct original_dst *target = bpf_map_lookup_elem(&map_dns_target, &key);
  if (!target || !target->port || ctx->user_ip4 != target->ip ||
      ctx->user_port != target->port) {
    return 1;
  }
  struct original_dst *original =
      bpf_sk_storage_get(&map_dns_original, ctx->sk, 0, 0);
  if (original) {
    ctx->user_ip4 = original->ip;
    ctx->user_port = original->port;
  }
  return 1;
}

SEC("cgroup/connect4")
int cg_dns_connect4(struct bpf_sock_addr *ctx) {
  if (ctx->protocol != IPPROTO_UDP) {
    return 1;
  }
  return redirect_dns(ctx);
}

SEC("cgroup/sendmsg4")
int cg_dns_sendmsg4(struct bpf_sock_addr *ctx) {
  return redirect_dns(ctx);
}

SEC("cgroup/recvmsg4")
int cg_dns_recvmsg4(struct bpf_sock_addr *ctx) {
  return restore_dns(ctx);
}

SEC("cgroup/getpeername4")
int cg_dns_getpeername4(struct bpf_sock_addr *ctx) {
  return restore_dns(ctx);
}

SEC("cgroup/connect4")
int cg_connect4(struct bpf_sock_addr *ctx) {
  if (ctx->protocol != IPPROTO_TCP) {
    return 1;
  }

  if (is_proxy_process()) {
    return 1;
  }

  if (!is_allowed_process()) {
    return 1;
  }

  if (ctx->user_ip4 == bpf_htonl(0x7F000001)) {
    return 1;
  }

  __u16 tproxy_port = get_tproxy_port();
  if (tproxy_port == 0) {
    return 1;
  }

  // 获取当前 socket 的唯一标识 (cookie)
  __u64 cookie = bpf_get_socket_cookie(ctx);

  // 将原始目标地址存入 map_socks
  struct original_dst dst = {.ip = ctx->user_ip4, .port = ctx->user_port};
  bpf_map_update_elem(&map_socks, &cookie, &dst, BPF_ANY);

  // 修改目标地址为本地代理地址
  ctx->user_ip4 = bpf_htonl(0x7F000001); // 127.0.0.1
  ctx->user_port = bpf_htons(tproxy_port);

  return 1; // 允许连接继续
}

SEC("sockops")
int record_established(struct bpf_sock_ops *ctx) {
  if (is_proxy_process()) {
    return 0;
  }

  if (ctx->op == BPF_SOCK_OPS_STATE_CB) {
    if (ctx->args[1] == BPF_TCP_CLOSE) {
      struct client_addr key = {
          .ip = ctx->local_ip4,
          .port = ctx->local_port,
      };
      bpf_map_delete_elem(&map_original_dst, &key);
    }
    return 0;
  }

  if (ctx->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
    return 0;
  }

  __u64 cookie = bpf_get_socket_cookie(ctx);
  struct original_dst *dst = bpf_map_lookup_elem(&map_socks, &cookie);
  if (!dst) {
    return 0;
  }

  struct client_addr key = {
      .ip = ctx->local_ip4,
      .port = ctx->local_port,
  };
  bpf_map_update_elem(&map_original_dst, &key, dst, BPF_ANY);
  bpf_sock_ops_cb_flags_set(ctx, ctx->bpf_sock_ops_cb_flags |
                                     BPF_SOCK_OPS_STATE_CB_FLAG);
  bpf_map_delete_elem(&map_socks, &cookie);
  return 0;
}

SEC("cgroup/getsockopt")
int cg_getsockopt(struct bpf_sockopt *ctx) {
  if (!is_proxy_process()) {
    return 1;
  }

  if (ctx->level != SOL_IP || ctx->optname != SO_ORIGINAL_DST) {
    return 1;
  }

  if (ctx->optlen < sizeof(struct sockaddr_in)) {
    ctx->retval = -EINVAL;
    return 1;
  }

  struct sockaddr_in *addr = ctx->optval;
  if ((void *)(addr + 1) > ctx->optval_end) {
    ctx->retval = -EINVAL;
    return 1;
  }

  if (!ctx->sk) {
    return 1;
  }

  struct client_addr key = {
      .ip = ctx->sk->dst_ip4,
      .port = bpf_ntohs(ctx->sk->dst_port),
  };
  struct original_dst *dst = bpf_map_lookup_elem(&map_original_dst, &key);
  if (!dst) {
    return 1;
  }

  addr->sin_family = AF_INET;
  addr->sin_port = dst->port;
  addr->sin_addr.s_addr = dst->ip;
  addr->__pad[0] = 0;
  addr->__pad[1] = 0;
  addr->__pad[2] = 0;
  addr->__pad[3] = 0;
  addr->__pad[4] = 0;
  addr->__pad[5] = 0;
  addr->__pad[6] = 0;
  addr->__pad[7] = 0;

  ctx->optlen = sizeof(*addr);
  ctx->retval = 0;
  return 1;
}

char LICENSE[] SEC("license") = "GPL";
