//go:build ignore
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// Global constant to filter events by target network namespace.
// Populated by the Go loader before the program is loaded into the kernel.
volatile const __u64 target_netns = 0;

// Minimal layout definition of struct sock / sock_common to support relocations
// without requiring the massive vmlinux.h header file.
struct sock_common {
    union {
        struct {
            __be32 skc_daddr;
            __be32 skc_rcv_saddr;
        };
    };
    union {
        struct {
            __be16 skc_dport;
            __u16  skc_num;
        };
    };
};

struct sock {
    struct sock_common __sk_common;
};

// Event struct matching the Go side representation
struct event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
};

// Ring buffer map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} events SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int kprobe_tcp_v4_connect(struct pt_regs *ctx) {
    // SECURITY PATCH: Namespace Isolation.
    // Discard events originating from other containers sharing the same node.
    __u64 current_netns = bpf_get_netns_cookie(NULL);
    if (target_netns != 0 && current_netns != target_netns) {
        return 0; 
    }

    // PT_REGS_PARM1 retrieves the first argument (struct sock*) of tcp_v4_connect
    #if defined(__TARGET_ARCH_x86)
    struct sock *sk = (struct sock *)ctx->di;
    #elif defined(__TARGET_ARCH_arm64)
    struct sock *sk = (struct sock *)ctx->regs[0];
    #else
    struct sock *sk = NULL;
    #endif

    if (!sk) {
        return 0;
    }

    struct event *ev;
    ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) {
        return 0;
    }

    // Safely read socket fields using BPF helper function
    bpf_probe_read_kernel(&ev->src_ip, sizeof(ev->src_ip), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&ev->dst_ip, sizeof(ev->dst_ip), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&ev->dst_port, sizeof(ev->dst_port), &sk->__sk_common.skc_dport);
    
    __u16 lport = 0;
    bpf_probe_read_kernel(&lport, sizeof(lport), &sk->__sk_common.skc_num);
    ev->src_port = bpf_htons(lport); // Convert to network byte order
    ev->proto = 6; // TCP

    bpf_ringbuf_submit(ev, 0);
    return 0;
}
