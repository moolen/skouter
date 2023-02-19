// This is a compact version of `vmlinux.h` to be used in the examples using C code.

#pragma once

typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;
typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;

#include "bpf_helpers.h"
#include <asm/byteorder.h>

enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC                = 0,
	BPF_MAP_TYPE_HASH                  = 1,
	BPF_MAP_TYPE_ARRAY                 = 2,
	BPF_MAP_TYPE_PROG_ARRAY            = 3,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY      = 4,
	BPF_MAP_TYPE_PERCPU_HASH           = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY          = 6,
	BPF_MAP_TYPE_STACK_TRACE           = 7,
	BPF_MAP_TYPE_CGROUP_ARRAY          = 8,
	BPF_MAP_TYPE_LRU_HASH              = 9,
	BPF_MAP_TYPE_LRU_PERCPU_HASH       = 10,
	BPF_MAP_TYPE_LPM_TRIE              = 11,
	BPF_MAP_TYPE_ARRAY_OF_MAPS         = 12,
	BPF_MAP_TYPE_HASH_OF_MAPS          = 13,
	BPF_MAP_TYPE_DEVMAP                = 14,
	BPF_MAP_TYPE_SOCKMAP               = 15,
	BPF_MAP_TYPE_CPUMAP                = 16,
	BPF_MAP_TYPE_XSKMAP                = 17,
	BPF_MAP_TYPE_SOCKHASH              = 18,
	BPF_MAP_TYPE_CGROUP_STORAGE        = 19,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY   = 20,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
	BPF_MAP_TYPE_QUEUE                 = 22,
	BPF_MAP_TYPE_STACK                 = 23,
	BPF_MAP_TYPE_SK_STORAGE            = 24,
	BPF_MAP_TYPE_DEVMAP_HASH           = 25,
	BPF_MAP_TYPE_STRUCT_OPS            = 26,
	BPF_MAP_TYPE_RINGBUF               = 27,
	BPF_MAP_TYPE_INODE_STORAGE         = 28,
};

typedef __u16 __sum16;

struct ethhdr {
	unsigned char h_dest[6];
	unsigned char h_source[6];
	__be16 h_proto;
};

struct iphdr {
	__u8 ihl: 4;
	__u8 version: 4;
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__sum16 check;
	__be32 saddr;
	__be32 daddr;
};

struct tcphdr {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
	__be16	window;
	__sum16	check;
	__be16	urg_ptr;
};

struct udphdr {
	__be16	source;
	__be16	dest;
	__be16	len;
	__sum16	check;
};

enum {
	BPF_ANY     = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST   = 2,
	BPF_F_LOCK  = 4,
};

/* flags for BPF_MAP_CREATE command */
enum {
	BPF_F_NO_PREALLOC	= (1U << 0),
/* Instead of having one common LRU list in the
 * BPF_MAP_TYPE_LRU_[PERCPU_]HASH map, use a percpu LRU list
 * which can scale and perform better.
 * Note, the LRU nodes (including free nodes) cannot be moved
 * across different LRU lists.
 */
	BPF_F_NO_COMMON_LRU	= (1U << 1),
/* Specify numa node during map creation */
	BPF_F_NUMA_NODE		= (1U << 2),

/* Flags for accessing BPF object from syscall side. */
	BPF_F_RDONLY		= (1U << 3),
	BPF_F_WRONLY		= (1U << 4),

/* Flag for stack_map, store build_id+offset instead of pointer */
	BPF_F_STACK_BUILD_ID	= (1U << 5),

/* Zero-initialize hash function seed. This should only be used for testing. */
	BPF_F_ZERO_SEED		= (1U << 6),

/* Flags for accessing BPF object from program side. */
	BPF_F_RDONLY_PROG	= (1U << 7),
	BPF_F_WRONLY_PROG	= (1U << 8),

/* Clone map from listener for newly accepted socket */
	BPF_F_CLONE		= (1U << 9),

/* Enable memory-mapping BPF map */
	BPF_F_MMAPABLE		= (1U << 10),

/* Share perf_event among processes */
	BPF_F_PRESERVE_ELEMS	= (1U << 11),

/* Create a map that is suitable to be an inner map with dynamic max entries */
	BPF_F_INNER_MAP		= (1U << 12),
};


/* BPF_FUNC_perf_event_output, BPF_FUNC_perf_event_read and
 * BPF_FUNC_perf_event_read_value flags.
 */
#define BPF_F_INDEX_MASK 0xffffffffULL
#define BPF_F_CURRENT_CPU BPF_F_INDEX_MASK

#if defined(__TARGET_ARCH_x86)
struct pt_regs {
	/*
	 * C ABI says these regs are callee-preserved. They aren't saved on kernel entry
	 * unless syscall needs a complete, fully filled "struct pt_regs".
	 */
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long rbp;
	unsigned long rbx;
	/* These regs are callee-clobbered. Always saved on kernel entry. */
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long rax;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
	/*
	 * On syscall entry, this is syscall#. On CPU exception, this is error code.
	 * On hw interrupt, it's IRQ number:
	 */
	unsigned long orig_rax;
	/* Return frame for iretq */
	unsigned long rip;
	unsigned long cs;
	unsigned long eflags;
	unsigned long rsp;
	unsigned long ss;
	/* top of stack page */
};
#endif /* __TARGET_ARCH_x86 */
