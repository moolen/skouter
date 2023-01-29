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
  __u32 key;
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
#define METRICS_INGRESS_TXID_MISMATCH 4
#define METRICS_INGRESS_ROGUE_DNS 5

// TODO: make these metrics per-pod
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 5);
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

void metrics_inc_blocked_addr(__u32 addr) {
  __u32 init_val = 1;
  __u32 *count = bpf_map_lookup_elem(&metrics_blocked_addr, &addr);
  if (!count) {
    bpf_map_update_elem(&metrics_blocked_addr, &addr, &init_val, BPF_ANY);
    return;
  }
  __sync_fetch_and_add(count, 1);
}

// store dns transaction id (+ip/port)
// to impede DNS spoofing/poisoning attacks
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1 << 16);
  __type(key, __u64);  // ip src + udp src + dns id
  __type(value, __u8); // noop
} dns_tracker SEC(".maps");

#define DNS_CHECK_SOURCE 1
#define DNS_CHECK_DEST 2

__u64 get_dns_key(struct __sk_buff *skb, __u8 check_type) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct iphdr *ip = (data);
  struct udphdr *udp = (data + sizeof(struct iphdr));
  __u16 *dns_id = (data + sizeof(struct iphdr) + sizeof(struct udphdr));
  if (data + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(__u16) >
      data_end) {
    return -1;
  }

  // The dns key is stored as a triplet containing ip source/dest address, udp
  // source/dest port and dns tx id key layout:
  // {32bit ip address} {16bit port} {16bit dns tx id}
  __u64 out = 0;
  if (check_type == DNS_CHECK_SOURCE) {
    out = ip->saddr << 31;
    out += udp->source << 15;
  } else if (check_type == DNS_CHECK_DEST) {
    out = ip->daddr << 31;
    out += udp->dest << 15;
  }
  out += *dns_id;
  return out;
}

// stores the dns id of a given skb
// returns 0 on success, negative otherwise
int store_dns_id(__u32 pod_key, struct __sk_buff *skb) {
  __u64 dns_id = get_dns_key(skb, DNS_CHECK_SOURCE);
  if (dns_id <= 0) {
    return -1;
  }
  __u8 val = 1;
  bpf_map_update_elem(&dns_tracker, &dns_id, &val, BPF_ANY);
  return 0;
}

// looks up dns transaction id
// and purges it if found.
// returns 0 on success, negative otherwise.
int lookup_dns_id(__u32 pod_key, struct __sk_buff *skb) {
  __u64 dns_id = get_dns_key(skb, DNS_CHECK_DEST);
  if (dns_id <= 0) {
    return -1;
  }
  __u8 *ret = bpf_map_lookup_elem(&dns_tracker, &dns_id);
  if (ret == NULL) {
    return -1;
  }
  bpf_map_delete_elem(&dns_tracker, &dns_id);
  return 0;
}

volatile const __u32 audit_mode = 0;

int is_audit_mode() { return audit_mode; }

SEC("cgroup_skb/ingress")
int capture_packets(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  const __u8 dns_offset = sizeof(struct iphdr) + sizeof(struct udphdr);

  struct iphdr *ip = (data);
  struct udphdr *udp = (data + sizeof(struct iphdr));

  // return early if not enough data
  if (data + dns_offset > data_end) {
    return 1;
  }

  if (ip->protocol != PROTO_UDP) {
    return 1;
  }

  if (udp->source != PORT_DNS && udp->dest != PORT_DNS) {
    return 1;
  }

  // first, check if pod is subject to egress policies
  // if not, return early
  __u32 key = ip->daddr;
  __u32 *inner_map = bpf_map_lookup_elem(&egress_config, &key);
  if (inner_map == NULL) {
    return 1;
  }

  __u32 *dns_upstream_addr = bpf_map_lookup_elem(&dns_config, &ip->saddr);
  if (dns_upstream_addr == NULL) {
    metrics_inc(METRICS_INGRESS_ROGUE_DNS);
    return 1;
  }

  int ret = lookup_dns_id(key, skb);
  if (ret != 0) {
    metrics_inc(METRICS_INGRESS_TXID_MISMATCH);
    return 1;
  }

  struct event *ev;
  ev = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
  if (!ev) {
    return 1;
  }

  ev->key = key;
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

  // TODO:
  // - support DNS over TCP
  bpf_ringbuf_submit(ev, 0);
  return 1;
}

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
    store_dns_id(key, skb);
    metrics_inc(METRICS_EGRESS_DNS);
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
