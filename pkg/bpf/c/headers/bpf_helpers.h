/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BPF_HELPERS__
#define __BPF_HELPERS__

#ifndef FORCE_READ
#define FORCE_READ(X) (*(volatile typeof(X) *)&X)
#endif

/*
 * Note that bpf programs need to include either
 * vmlinux.h (auto-generated from BTF) or linux/types.h
 * in advance since bpf_helper_defs.h uses such types
 * as __u64.
 */
/* user accessible mirror of in-kernel sk_buff.
 * new fields can only be added to the end of this structure
 */
struct __sk_buff {
  __u32 len;
  __u32 pkt_type;
  __u32 mark;
  __u32 queue_mapping;
  __u32 protocol;
  __u32 vlan_present;
  __u32 vlan_tci;
  __u32 vlan_proto;
  __u32 priority;
  __u32 ingress_ifindex;
  __u32 ifindex;
  __u32 tc_index;
  __u32 cb[5];
  __u32 hash;
  __u32 tc_classid;
  __u32 data;
  __u32 data_end;
  __u32 napi_id;

  /* Accessed by BPF_PROG_TYPE_sk_skb types from here to ... */
  __u32 family;
  __u32 remote_ip4;    /* Stored in network byte order */
  __u32 local_ip4;     /* Stored in network byte order */
  __u32 remote_ip6[4]; /* Stored in network byte order */
  __u32 local_ip6[4];  /* Stored in network byte order */
  __u32 remote_port;   /* Stored in network byte order */
  __u32 local_port;    /* stored in host byte order */
                       /* ... here. */
};

#define __bpf_md_ptr(type, name)                                               \
  union {                                                                      \
    type name;                                                                 \
    __u64 : 64;                                                                \
  } __attribute__((aligned(8)))

#define BPF_F_RECOMPUTE_CSUM		(1ULL << 0)
#define BPF_F_INVALIDATE_HASH		(1ULL << 1)

/* User accessible data for SK_LOOKUP programs. Add new fields at the end. */
struct bpf_sk_lookup {
  union {
    __bpf_md_ptr(struct bpf_sock *, sk); /* Selected socket */
    __u64 cookie; /* Non-zero if socket was selected in PROG_TEST_RUN */
  };

  __u32 family;          /* Protocol family (AF_INET, AF_INET6) */
  __u32 protocol;        /* IP protocol (IPPROTO_TCP, IPPROTO_UDP) */
  __u32 remote_ip4;      /* Network byte order */
  __u32 remote_ip6[4];   /* Network byte order */
  __be16 remote_port;    /* Network byte order */
  __u16 : 16;            /* Zero padding */
  __u32 local_ip4;       /* Network byte order */
  __u32 local_ip6[4];    /* Network byte order */
  __u32 local_port;      /* Host byte order */
  __u32 ingress_ifindex; /* The arriving interface. Determined by inet_iif. */
};

/* user accessible metadata for SK_MSG packet hook, new fields must
 * be added to the end of this structure
 */
struct sk_msg_md {
  __bpf_md_ptr(void *, data);
  __bpf_md_ptr(void *, data_end);

  __u32 family;
  __u32 remote_ip4;    /* Stored in network byte order */
  __u32 local_ip4;     /* Stored in network byte order */
  __u32 remote_ip6[4]; /* Stored in network byte order */
  __u32 local_ip6[4];  /* Stored in network byte order */
  __u32 remote_port;   /* Stored in network byte order */
  __u32 local_port;    /* stored in host byte order */
  __u32 size;          /* Total size of sk_msg */

  __bpf_md_ptr(struct bpf_sock *, sk); /* current socket */
};

enum sk_action {
  SK_DROP = 0,
  SK_PASS,
};

enum {
	BPF_FIB_LOOKUP_DIRECT  = (1U << 0),
	BPF_FIB_LOOKUP_OUTPUT  = (1U << 1),
};

enum {
	BPF_FIB_LKUP_RET_SUCCESS,      /* lookup successful */
	BPF_FIB_LKUP_RET_BLACKHOLE,    /* dest is blackholed; can be dropped */
	BPF_FIB_LKUP_RET_UNREACHABLE,  /* dest is unreachable; can be dropped */
	BPF_FIB_LKUP_RET_PROHIBIT,     /* dest not allowed; can be dropped */
	BPF_FIB_LKUP_RET_NOT_FWDED,    /* packet is not forwarded */
	BPF_FIB_LKUP_RET_FWD_DISABLED, /* fwding is not enabled on ingress */
	BPF_FIB_LKUP_RET_UNSUPP_LWT,   /* fwd requires encapsulation */
	BPF_FIB_LKUP_RET_NO_NEIGH,     /* no neighbor entry for nh */
	BPF_FIB_LKUP_RET_FRAG_NEEDED,  /* fragmentation required to fwd */
};


#define AF_INET		2	/* Internet IP Protocol 	*/

struct bpf_fib_lookup {
	/* input:  network family for lookup (AF_INET, AF_INET6)
	 * output: network family of egress nexthop
	 */
	__u8	family;

	/* set if lookup is to consider L4 data - e.g., FIB rules */
	__u8	l4_protocol;
	__be16	sport;
	__be16	dport;

	union {	/* used for MTU check */
		/* input to lookup */
		__u16	tot_len; /* L3 length from network hdr (iph->tot_len) */

		/* output: MTU value */
		__u16	mtu_result;
	};
	/* input: L3 device index for lookup
	 * output: device index from FIB lookup
	 */
	__u32	ifindex;

	union {
		/* inputs to lookup */
		__u8	tos;		/* AF_INET  */
		__be32	flowinfo;	/* AF_INET6, flow_label + priority */

		/* output: metric of fib result (IPv4/IPv6 only) */
		__u32	rt_metric;
	};

	union {
		__be32		ipv4_src;
		__u32		ipv6_src[4];  /* in6_addr; network order */
	};

	/* input to bpf_fib_lookup, ipv{4,6}_dst is destination address in
	 * network header. output: bpf_fib_lookup sets to gateway address
	 * if FIB lookup returns gateway route
	 */
	union {
		__be32		ipv4_dst;
		__u32		ipv6_dst[4];  /* in6_addr; network order */
	};

	/* output */
	__be16	h_vlan_proto;
	__be16	h_vlan_TCI;
	__u8	smac[6];     /* ETH_ALEN */
	__u8	dmac[6];     /* ETH_ALEN */
};


#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_RECLASSIFY 1
#define TC_ACT_SHOT 2
#define TC_ACT_PIPE 3
#define TC_ACT_STOLEN 4
#define TC_ACT_QUEUED 5
#define TC_ACT_REPEAT 6
#define TC_ACT_REDIRECT 7
#define TC_ACT_TRAP 8

/* User bpf_sock_ops struct to access socket values and specify request ops
 * and their replies.
 * Some of this fields are in network (bigendian) byte order and may need
 * to be converted before use (bpf_ntohl() defined in samples/bpf/bpf_endian.h).
 * New fields can only be added at the end of this structure
 */
struct bpf_sock_ops {
  __u32 op;
  union {
    __u32 args[4];      /* Optionally passed to bpf program */
    __u32 reply;        /* Returned by bpf program	    */
    __u32 replylong[4]; /* Optionally returned by bpf prog  */
  };
  __u32 family;
  __u32 remote_ip4;    /* Stored in network byte order */
  __u32 local_ip4;     /* Stored in network byte order */
  __u32 remote_ip6[4]; /* Stored in network byte order */
  __u32 local_ip6[4];  /* Stored in network byte order */
  __u32 remote_port;   /* Stored in network byte order */
  __u32 local_port;    /* stored in host byte order */
  __u32 is_fullsock;   /* Some TCP fields are only valid if
                        * there is a full socket. If not, the
                        * fields read as zero.
                        */
  __u32 snd_cwnd;
  __u32 srtt_us;               /* Averaged RTT << 3 in usecs */
  __u32 bpf_sock_ops_cb_flags; /* flags defined in uapi/linux/tcp.h */
  __u32 state;
  __u32 rtt_min;
  __u32 snd_ssthresh;
  __u32 rcv_nxt;
  __u32 snd_nxt;
  __u32 snd_una;
  __u32 mss_cache;
  __u32 ecn_flags;
  __u32 rate_delivered;
  __u32 rate_interval_us;
  __u32 packets_out;
  __u32 retrans_out;
  __u32 total_retrans;
  __u32 segs_in;
  __u32 data_segs_in;
  __u32 segs_out;
  __u32 data_segs_out;
  __u32 lost_out;
  __u32 sacked_out;
  __u32 sk_txhash;
  __u64 bytes_received;
  __u64 bytes_acked;
  __bpf_md_ptr(struct bpf_sock *, sk);
  /* [skb_data, skb_data_end) covers the whole TCP header.
   *
   * BPF_SOCK_OPS_PARSE_HDR_OPT_CB: The packet received
   * BPF_SOCK_OPS_HDR_OPT_LEN_CB:   Not useful because the
   *                                header has not been written.
   * BPF_SOCK_OPS_WRITE_HDR_OPT_CB: The header and options have
   *				  been written so far.
   * BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:  The SYNACK that concludes
   *					the 3WHS.
   * BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: The ACK that concludes
   *					the 3WHS.
   *
   * bpf_load_hdr_opt() can also be used to read a particular option.
   */
  __bpf_md_ptr(void *, skb_data);
  __bpf_md_ptr(void *, skb_data_end);
  __u32 skb_len;       /* The total length of a packet.
                        * It includes the header, options,
                        * and payload.
                        */
  __u32 skb_tcp_flags; /* tcp_flags of the header.  It provides
                        * an easy way to check for tcp_flags
                        * without parsing skb_data.
                        *
                        * In particular, the skb_tcp_flags
                        * will still be available in
                        * BPF_SOCK_OPS_HDR_OPT_LEN even though
                        * the outgoing header has not
                        * been written yet.
                        */
};

/* List of known BPF sock_ops operators.
 * New entries can only be added at the end
 */
enum {
  BPF_SOCK_OPS_VOID,
  BPF_SOCK_OPS_TIMEOUT_INIT,           /* Should return SYN-RTO value to use or
                                        * -1 if default value should be used
                                        */
  BPF_SOCK_OPS_RWND_INIT,              /* Should return initial advertized
                                        * window (in packets) or -1 if default
                                        * value should be used
                                        */
  BPF_SOCK_OPS_TCP_CONNECT_CB,         /* Calls BPF program right before an
                                        * active connection is initialized
                                        */
  BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB,  /* Calls BPF program when an
                                        * active connection is
                                        * established
                                        */
  BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB, /* Calls BPF program when a
                                        * passive connection is
                                        * established
                                        */
  BPF_SOCK_OPS_NEEDS_ECN,              /* If connection's congestion control
                                        * needs ECN
                                        */
  BPF_SOCK_OPS_BASE_RTT,               /* Get base RTT. The correct value is
                                        * based on the path and may be
                                        * dependent on the congestion control
                                        * algorithm. In general it indicates
                                        * a congestion threshold. RTTs above
                                        * this indicate congestion
                                        */
  BPF_SOCK_OPS_RTO_CB,                 /* Called when an RTO has triggered.
                                        * Arg1: value of icsk_retransmits
                                        * Arg2: value of icsk_rto
                                        * Arg3: whether RTO has expired
                                        */
  BPF_SOCK_OPS_RETRANS_CB,             /* Called when skb is retransmitted.
                                        * Arg1: sequence number of 1st byte
                                        * Arg2: # segments
                                        * Arg3: return value of
                                        *       tcp_transmit_skb (0 => success)
                                        */
  BPF_SOCK_OPS_STATE_CB,               /* Called when TCP changes state.
                                        * Arg1: old_state
                                        * Arg2: new_state
                                        */
  BPF_SOCK_OPS_TCP_LISTEN_CB,          /* Called on listen(2), right after
                                        * socket transition to LISTEN state.
                                        */
  BPF_SOCK_OPS_RTT_CB,                 /* Called on every RTT.
                                        */
  BPF_SOCK_OPS_PARSE_HDR_OPT_CB,       /* Parse the header option.
                                        * It will be called to handle
                                        * the packets received at
                                        * an already established
                                        * connection.
                                        *
                                        * sock_ops->skb_data:
                                        * Referring to the received skb.
                                        * It covers the TCP header only.
                                        *
                                        * bpf_load_hdr_opt() can also
                                        * be used to search for a
                                        * particular option.
                                        */
  BPF_SOCK_OPS_HDR_OPT_LEN_CB,         /* Reserve space for writing the
                                        * header option later in
                                        * BPF_SOCK_OPS_WRITE_HDR_OPT_CB.
                                        * Arg1: bool want_cookie. (in
                                        *       writing SYNACK only)
                                        *
                                        * sock_ops->skb_data:
                                        * Not available because no header has
                                        * been	written yet.
                                        *
                                        * sock_ops->skb_tcp_flags:
                                        * The tcp_flags of the
                                        * outgoing skb. (e.g. SYN, ACK, FIN).
                                        *
                                        * bpf_reserve_hdr_opt() should
                                        * be used to reserve space.
                                        */
  BPF_SOCK_OPS_WRITE_HDR_OPT_CB,       /* Write the header options
                                        * Arg1: bool want_cookie. (in
                                        *       writing SYNACK only)
                                        *
                                        * sock_ops->skb_data:
                                        * Referring to the outgoing skb.
                                        * It covers the TCP header
                                        * that has already been written
                                        * by the kernel and the
                                        * earlier bpf-progs.
                                        *
                                        * sock_ops->skb_tcp_flags:
                                        * The tcp_flags of the outgoing
                                        * skb. (e.g. SYN, ACK, FIN).
                                        *
                                        * bpf_store_hdr_opt() should
                                        * be used to write the
                                        * option.
                                        *
                                        * bpf_load_hdr_opt() can also
                                        * be used to search for a
                                        * particular option that
                                        * has already been written
                                        * by the kernel or the
                                        * earlier bpf-progs.
                                        */
};

/* BPF_FUNC_clone_redirect and BPF_FUNC_redirect flags. */
enum {
  BPF_F_INGRESS = (1ULL << 0),
};

#include "bpf_endian.h"
#include "bpf_helper_defs.h"

#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

/* llvm builtin functions that eBPF C program may use to
 * emit BPF_LD_ABS and BPF_LD_IND instructions
 */
struct sk_buff;
unsigned long long load_byte(void *skb,
                             unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
                             unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
                             unsigned long long off) asm("llvm.bpf.load.word");

/*
 * Helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by libbpf depending on the context (BPF programs, BPF maps,
 * extern variables, etc).
 * To allow use of SEC() with externs (e.g., for extern .maps declarations),
 * make sure __attribute__((unused)) doesn't trigger compilation warning.
 */
#define SEC(name)                                                              \
  _Pragma("GCC diagnostic push")                                               \
      _Pragma("GCC diagnostic ignored \"-Wignored-attributes\"")               \
          __attribute__((section(name), used)) _Pragma("GCC diagnostic pop")

/* Avoid 'linux/stddef.h' definition of '__always_inline'. */
#undef __always_inline
#define __always_inline inline __attribute__((always_inline))

#ifndef __noinline
#define __noinline __attribute__((noinline))
#endif
#ifndef __weak
#define __weak __attribute__((weak))
#endif

/*
 * Use __hidden attribute to mark a non-static BPF subprogram effectively
 * static for BPF verifier's verification algorithm purposes, allowing more
 * extensive and permissive BPF verification process, taking into account
 * subprogram's caller context.
 */
#define __hidden __attribute__((visibility("hidden")))

/* When utilizing vmlinux.h with BPF CO-RE, user BPF programs can't include
 * any system-level headers (such as stddef.h, linux/version.h, etc), and
 * commonly-used macros like NULL and KERNEL_VERSION aren't available through
 * vmlinux.h. This just adds unnecessary hurdles and forces users to re-define
 * them on their own. So as a convenience, provide such definitions here.
 */
#ifndef NULL
#define NULL ((void *)0)
#endif

#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a, b, c)                                                \
  (((a) << 16) + ((b) << 8) + ((c) > 255 ? 255 : (c)))
#endif

/*
 * Helper macros to manipulate data structures
 */
#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((unsigned long)&((TYPE *)0)->MEMBER)
#endif
#ifndef container_of
#define container_of(ptr, type, member)                                        \
  ({                                                                           \
    void *__mptr = (void *)(ptr);                                              \
    ((type *)(__mptr - offsetof(type, member)));                               \
  })
#endif

/*
 * Helper macro to throw a compilation error if __bpf_unreachable() gets
 * built into the resulting code. This works given BPF back end does not
 * implement __builtin_trap(). This is useful to assert that certain paths
 * of the program code are never used and hence eliminated by the compiler.
 *
 * For example, consider a switch statement that covers known cases used by
 * the program. __bpf_unreachable() can then reside in the default case. If
 * the program gets extended such that a case is not covered in the switch
 * statement, then it will throw a build error due to the default case not
 * being compiled out.
 */
#ifndef __bpf_unreachable
#define __bpf_unreachable() __builtin_trap()
#endif

/*
 * Helper function to perform a tail call with a constant/immediate map slot.
 */
#if __clang_major__ >= 8 && defined(__bpf__)
static __always_inline void bpf_tail_call_static(void *ctx, const void *map,
                                                 const __u32 slot) {
  if (!__builtin_constant_p(slot))
    __bpf_unreachable();

  /*
   * Provide a hard guarantee that LLVM won't optimize setting r2 (map
   * pointer) and r3 (constant map index) from _different paths_ ending
   * up at the _same_ call insn as otherwise we won't be able to use the
   * jmpq/nopl retpoline-free patching by the x86-64 JIT in the kernel
   * given they mismatch. See also d2e4c1e6c294 ("bpf: Constant map key
   * tracking for prog array pokes") for details on verifier tracking.
   *
   * Note on clobber list: we need to stay in-line with BPF calling
   * convention, so even if we don't end up using r0, r4, r5, we need
   * to mark them as clobber so that LLVM doesn't end up using them
   * before / after the call.
   */
  asm volatile("r1 = %[ctx]\n\t"
               "r2 = %[map]\n\t"
               "r3 = %[slot]\n\t"
               "call 12" ::[ctx] "r"(ctx),
               [map] "r"(map), [slot] "i"(slot)
               : "r0", "r1", "r2", "r3", "r4", "r5");
}
#endif

/*
 * Helper structure used by eBPF C program
 * to describe BPF map attributes to libbpf loader
 */
struct bpf_map_def {
  unsigned int type;
  unsigned int key_size;
  unsigned int value_size;
  unsigned int max_entries;
  unsigned int map_flags;
};

enum libbpf_pin_type {
  LIBBPF_PIN_NONE,
  /* PIN_BY_NAME: pin maps by name (in /sys/fs/bpf by default) */
  LIBBPF_PIN_BY_NAME,
};

enum libbpf_tristate {
  TRI_NO = 0,
  TRI_YES = 1,
  TRI_MODULE = 2,
};

#define __kconfig __attribute__((section(".kconfig")))
#define __ksym __attribute__((section(".ksyms")))

#ifndef ___bpf_concat
#define ___bpf_concat(a, b) a##b
#endif
#ifndef ___bpf_apply
#define ___bpf_apply(fn, n) ___bpf_concat(fn, n)
#endif
#ifndef ___bpf_nth
#define ___bpf_nth(_, _1, _2, _3, _4, _5, _6, _7, _8, _9, _a, _b, _c, N, ...) N
#endif
#ifndef ___bpf_narg
#define ___bpf_narg(...)                                                       \
  ___bpf_nth(_, ##__VA_ARGS__, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#endif

#define ___bpf_fill0(arr, p, x)                                                \
  do {                                                                         \
  } while (0)
#define ___bpf_fill1(arr, p, x) arr[p] = x
#define ___bpf_fill2(arr, p, x, args...)                                       \
  arr[p] = x;                                                                  \
  ___bpf_fill1(arr, p + 1, args)
#define ___bpf_fill3(arr, p, x, args...)                                       \
  arr[p] = x;                                                                  \
  ___bpf_fill2(arr, p + 1, args)
#define ___bpf_fill4(arr, p, x, args...)                                       \
  arr[p] = x;                                                                  \
  ___bpf_fill3(arr, p + 1, args)
#define ___bpf_fill5(arr, p, x, args...)                                       \
  arr[p] = x;                                                                  \
  ___bpf_fill4(arr, p + 1, args)
#define ___bpf_fill6(arr, p, x, args...)                                       \
  arr[p] = x;                                                                  \
  ___bpf_fill5(arr, p + 1, args)
#define ___bpf_fill7(arr, p, x, args...)                                       \
  arr[p] = x;                                                                  \
  ___bpf_fill6(arr, p + 1, args)
#define ___bpf_fill8(arr, p, x, args...)                                       \
  arr[p] = x;                                                                  \
  ___bpf_fill7(arr, p + 1, args)
#define ___bpf_fill9(arr, p, x, args...)                                       \
  arr[p] = x;                                                                  \
  ___bpf_fill8(arr, p + 1, args)
#define ___bpf_fill10(arr, p, x, args...)                                      \
  arr[p] = x;                                                                  \
  ___bpf_fill9(arr, p + 1, args)
#define ___bpf_fill11(arr, p, x, args...)                                      \
  arr[p] = x;                                                                  \
  ___bpf_fill10(arr, p + 1, args)
#define ___bpf_fill12(arr, p, x, args...)                                      \
  arr[p] = x;                                                                  \
  ___bpf_fill11(arr, p + 1, args)
#define ___bpf_fill(arr, args...)                                              \
  ___bpf_apply(___bpf_fill, ___bpf_narg(args))(arr, 0, args)

/*
 * BPF_SEQ_PRINTF to wrap bpf_seq_printf to-be-printed values
 * in a structure.
 */
#define BPF_SEQ_PRINTF(seq, fmt, args...)                                      \
  ({                                                                           \
    static const char ___fmt[] = fmt;                                          \
    unsigned long long ___param[___bpf_narg(args)];                            \
                                                                               \
    _Pragma("GCC diagnostic push")                                             \
        _Pragma("GCC diagnostic ignored \"-Wint-conversion\"")                 \
            ___bpf_fill(___param, args);                                       \
    _Pragma("GCC diagnostic pop")                                              \
                                                                               \
        bpf_seq_printf(seq, ___fmt, sizeof(___fmt), ___param,                  \
                       sizeof(___param));                                      \
  })

/*
 * BPF_SNPRINTF wraps the bpf_snprintf helper with variadic arguments instead of
 * an array of u64.
 */
#define BPF_SNPRINTF(out, out_size, fmt, args...)                              \
  ({                                                                           \
    static const char ___fmt[] = fmt;                                          \
    unsigned long long ___param[___bpf_narg(args)];                            \
                                                                               \
    _Pragma("GCC diagnostic push")                                             \
        _Pragma("GCC diagnostic ignored \"-Wint-conversion\"")                 \
            ___bpf_fill(___param, args);                                       \
    _Pragma("GCC diagnostic pop")                                              \
                                                                               \
        bpf_snprintf(out, out_size, ___fmt, ___param, sizeof(___param));       \
  })

#ifdef BPF_NO_GLOBAL_DATA
#define BPF_PRINTK_FMT_MOD
#else
#define BPF_PRINTK_FMT_MOD static const
#endif

#define __bpf_printk(fmt, ...)                                                 \
  ({                                                                           \
    BPF_PRINTK_FMT_MOD char ____fmt[] = fmt;                                   \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);                 \
  })

/*
 * __bpf_vprintk wraps the bpf_trace_vprintk helper with variadic arguments
 * instead of an array of u64.
 */
#define __bpf_vprintk(fmt, args...)                                            \
  ({                                                                           \
    static const char ___fmt[] = fmt;                                          \
    unsigned long long ___param[___bpf_narg(args)];                            \
                                                                               \
    _Pragma("GCC diagnostic push")                                             \
        _Pragma("GCC diagnostic ignored \"-Wint-conversion\"")                 \
            ___bpf_fill(___param, args);                                       \
    _Pragma("GCC diagnostic pop")                                              \
                                                                               \
        bpf_trace_vprintk(___fmt, sizeof(___fmt), ___param, sizeof(___param)); \
  })

/* Use __bpf_printk when bpf_printk call has 3 or fewer fmt args
 * Otherwise use __bpf_vprintk
 */
#define ___bpf_pick_printk(...)                                                \
  ___bpf_nth(_, ##__VA_ARGS__, __bpf_vprintk, __bpf_vprintk, __bpf_vprintk,    \
             __bpf_vprintk, __bpf_vprintk, __bpf_vprintk, __bpf_vprintk,       \
             __bpf_vprintk, __bpf_vprintk, __bpf_printk /*3*/,                 \
             __bpf_printk /*2*/, __bpf_printk /*1*/, __bpf_printk /*0*/)

/* Helper macro to print out debug messages */
#define bpf_printk(fmt, args...) ___bpf_pick_printk(args)(fmt, ##args)

#endif
