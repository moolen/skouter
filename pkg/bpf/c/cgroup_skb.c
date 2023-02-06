#include "headers/common.h"

#define PROTO_UDP 17
#define PORT_DNS 13568 // htons(53)

#define MAX_IP_ENTRIES 512
#define MAX_EGRESS_IPS 4096
#define MAX_EGRESS_CIDRS 256
#define MAX_PKT 768

#define TC_ALLOW 1
#define TC_BLOCK 2

struct event {
  __u16 len;
  __u32 pod_addr;
  __u16 pod_port;
  __u16 dst_port;
  __u32 dst_addr;
  u8 pkt[MAX_PKT];
};

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} events SEC(".maps");

// nested inside map used to block egress traffic
// lookup destination ip => allowed setting (TC_*)
struct pod_egress_config {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_EGRESS_IPS);
  __type(key, __u32);   // dest IPv4 address
  __type(value, __u32); // allowed setting
};

// nested outer map to lookup pod ip (source) => inner map (destination ip ->
// allowed setting)
struct {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, MAX_IP_ENTRIES);
  __type(key, __u32); // pod IPv4 address
  __uint(pinning, LIBBPF_PIN_BY_NAME);
  __array(values, struct pod_egress_config);
} egress_config SEC(".maps");

// value stored in egress_cidr_config below
// it contains a ip address as well as net mask
struct cidr_config_val {
  __u32 addr;
  __u32 mask;
};

// Force emitting struct cidr_config_val into the ELF.
const struct cidr_config_val *unused2 __attribute__((unused));

// nested map used to block egress traffic based on CIDR ranges
struct pod_egress_cidr_config {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_EGRESS_CIDRS);
  __type(key, __u32);   // 0=number of cidrs, 1..256 are CIDRs
  __type(value, __u64); // {IPv4 addr, subnet mask}
};

// nested outer map to lookup pod ip (source) => inner map (destination ip ->
// allowed setting)
struct {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, MAX_IP_ENTRIES);
  __type(key, __u32); // pod IPv4 address
  __uint(pinning, LIBBPF_PIN_BY_NAME);
  __array(values, struct pod_egress_cidr_config);
} egress_cidr_config SEC(".maps");

// map to store the upstream dns server address
// this is used to verify the dst address (egress) or
// src address (ingress).
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_IP_ENTRIES);
  __type(key, __u32);   // upstream dns server address
  __type(value, __u32); // noop
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} dns_config SEC(".maps");

// packet metrics
// the following #defines specify the indices in
// the the metrics map
#define METRICS_EGRESS_ALLOWED 1
#define METRICS_EGRESS_BLOCKED 2
#define METRICS_EGRESS_DNS 3
#define METRICS_RINGBUF_AVAIL_DATA 4
#define METRICS_RINGBUF_RING_SIZE 5
#define METRICS_RINGBUF_CONS_POS 6
#define METRICS_RINGBUF_PROD_POS 7

#define BPF_RB_AVAIL_DATA 0
#define BPF_RB_RING_SIZE 1
#define BPF_RB_CONS_POS 2
#define BPF_RB_PROD_POS 3

// TODO: make these metrics per-pod
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32);   // metric index, see #define above
  __type(value, __u32); // counter value
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} metrics SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32);   // src/dst ip address
  __type(value, __u32); // counter value
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} metrics_blocked_addr SEC(".maps");

// increments the metric with the given key
void metrics_inc(__u32 key) {
  __u32 init_val = 1;
  __u32 *count = bpf_map_lookup_elem(&metrics, &key);
  if (!count) {
    bpf_map_update_elem(&metrics, &key, &init_val, BPF_ANY);
    return;
  }
  __sync_fetch_and_add(count, 1);
}

// increments the metric with the given key
void metrics_set(__u32 key, __u32 val) {
  bpf_map_update_elem(&metrics, &key, &val, BPF_ANY);
}

void metrics_inc_blocked_addr(__u32 addr) {
  __u32 init_val = 1;
  __u32 *count = bpf_map_lookup_elem(&metrics_blocked_addr, &addr);
  if (!count) {
    bpf_map_update_elem(&metrics_blocked_addr, &addr, &init_val, BPF_ANY);
    return;
  }
  __sync_fetch_and_add(count, 1);
}

volatile const __u32 audit_mode = 0;

int is_audit_mode() { return audit_mode; }

// returns 1 if allowed
// returns 0 if blocked
int egress_ip_allowed(__u32 key, __u32 daddr) {
  __u32 *inner_map = bpf_map_lookup_elem(&egress_config, &key);
  if (inner_map == NULL) {
    // not subject to policies
    return TC_ALLOW;
  }
  __u8 *allowed = bpf_map_lookup_elem(inner_map, &daddr);
  if (allowed == NULL || *allowed != TC_ALLOW) {
    metrics_inc(METRICS_EGRESS_BLOCKED);

    if (is_audit_mode() == 1) {
      metrics_inc_blocked_addr(daddr);
      return TC_ALLOW;
    }
    return TC_BLOCK;
  }

  metrics_inc(METRICS_EGRESS_ALLOWED);
  return TC_ALLOW;
}

// returns 1 if allowed
// returns 0 if blocked
int egress_cidr_allowed(__u32 key, __u32 daddr) {
  __u32 *inner_map = bpf_map_lookup_elem(&egress_cidr_config, &key);
  if (inner_map == NULL) {
    // not subject to policies
    return TC_ALLOW;
  }

  // idx 0 stores the length of CIDRs for this particular array
  // It is stored to prevent unneeded iterations and correct handling
  // of the null value 0.0.0.0/0
  __u32 zero = 0;
  __u64 *len = bpf_map_lookup_elem(inner_map, &zero);
  if (len == NULL) {
    return TC_ALLOW;
  }

  for (int i = 1; i < MAX_EGRESS_CIDRS; i++) {
    if (i > *len) {
      return TC_BLOCK;
    }
    __u32 j = i;
    struct cidr_config_val *cidr = bpf_map_lookup_elem(inner_map, &j);
    if (cidr == NULL) {
      return TC_ALLOW;
    }
    if (cidr == NULL) {
      return TC_ALLOW;
    }
    if ((cidr->addr & cidr->mask) == (daddr & cidr->mask)) {
      return TC_ALLOW;
    }
  }
  return TC_BLOCK;
}

// return 0 on success
// return 1 on error
int forward_dns(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  const __u8 dns_offset = sizeof(struct iphdr) + sizeof(struct udphdr);

  struct iphdr *ip = (data);
  struct udphdr *udp = (data + sizeof(struct iphdr));
  if (data + dns_offset > data_end) {
    return 1;
  }

  struct event *ev;
  ev = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
  if (!ev) {
    return 1;
  }

  ev->pod_addr = ip->saddr;
  ev->pod_port = udp->source;
  ev->dst_port = udp->dest;
  ev->dst_addr = ip->daddr;
  for (int i = 0; i < MAX_PKT; i++) {
    if (dns_offset + i > ip->tot_len) {
      break;
    }
    int ok = bpf_skb_load_bytes(skb, dns_offset + i, &ev->pkt[i], 1);
    if (ok != 0) {
      break;
    }
    ev->len = i + 1;
  }

  __u32 avail_data = bpf_ringbuf_query(&events, BPF_RB_AVAIL_DATA);
  __u32 ring_size = bpf_ringbuf_query(&events, BPF_RB_RING_SIZE);
  __u32 cons_pos = bpf_ringbuf_query(&events, BPF_RB_CONS_POS);
  __u32 prod_pos = bpf_ringbuf_query(&events, BPF_RB_PROD_POS);
  metrics_set(METRICS_RINGBUF_AVAIL_DATA, avail_data);
  metrics_set(METRICS_RINGBUF_RING_SIZE, ring_size);
  metrics_set(METRICS_RINGBUF_CONS_POS, cons_pos);
  metrics_set(METRICS_RINGBUF_PROD_POS, prod_pos);

  bpf_ringbuf_submit(ev, 0);
  return 0;
}

SEC("cgroup_skb/egress")
int egress(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct iphdr *ip = (data);
  if (data + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end) {
    return TC_ALLOW;
  }

  __u32 key = ip->saddr;

  // check if pod is subject to egress policies
  __u32 *inner_map = bpf_map_lookup_elem(&egress_config, &key);
  if (inner_map == NULL) {
    return TC_ALLOW;
  }

  // pass traffic if destination is upstream dns server
  __u32 *ret = bpf_map_lookup_elem(&dns_config, &ip->daddr);
  if (ret != NULL && *ret == 1) {
    // dnsproxy uses a marked socket to make queries to the upstream
    // dns server. Traffic should be forwarded without blocking.
    if (skb->mark == 0x520) {
      return TC_ALLOW;
    }

    metrics_inc(METRICS_EGRESS_DNS);
    int ret = forward_dns(skb);

    // DNS query is blocked here and forwarded to th skouter DNS server
    // which will do the DNS lookup and send a response with a RAW socket
    if (ret == 0) {
      return TC_BLOCK;
    }
    return TC_ALLOW;
  }

  // bpf_printk("pod is subject to egress filter key=%d saddr=%d daddr=%d", key,
  //            ip->saddr, ip->daddr);

  if (egress_ip_allowed(key, ip->daddr) == TC_BLOCK &&
      egress_cidr_allowed(key, ip->daddr) == TC_BLOCK) {
    return TC_BLOCK;
  }

  return TC_ALLOW;
}

char __license[] SEC("license") = "Dual MIT/GPL";
