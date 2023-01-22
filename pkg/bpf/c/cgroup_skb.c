#include "headers/common.h"
#include <bpf/bpf_endian.h>
#include <linux/udp.h>

#define PROTO_UDP 17
#define PORT_DNS 13568 // htons(53)

#define MAX_IP_ENTRIES 256
#define MAX_LABELS 12
#define MAX_ANS_COUNT 1
#define MAX_ANS_ADDR 4
#define MAX_QNAME_LEN 64
#define MAX_PKT 512

#define TC_ALLOW 1
#define TC_BLOCK 2
#define TC_AUDIT 3

struct event {
  u8 len;
  __u32 pod_key;
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
  __uint(max_entries, MAX_IP_ENTRIES);
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
} pod_config SEC(".maps");

// map to store the upstream dns server address
// this is used to verify the dst address (egress) or
// src address (ingress).
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 20);
  __type(key, __u32);   // has just one entry
  __type(value, __u32); // upstream dns server address
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

__u32 key_for_addr(__u32 addr) { return bpf_ntohl(addr) % 255; }

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
  if (check_type == DNS_CHECK_SOURCE) {
    return ip->saddr + udp->source + *dns_id;
  } else if (check_type == DNS_CHECK_DEST) {
    return ip->daddr + udp->dest + *dns_id;
  }
  return -1;
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
  __be32 pod_key = key_for_addr(ip->daddr);
  __u32 *inner_map = bpf_map_lookup_elem(&pod_config, &pod_key);
  if (inner_map == NULL) {
    return 1;
  }

  __u32 key = 1;
  __u32 *dns_upstream_addr = bpf_map_lookup_elem(&dns_config, &key);
  if (dns_upstream_addr == NULL) {
    bpf_printk("no dns upstream addr in dns config");
    return 1;
  }

  if (ip->saddr != *dns_upstream_addr) {
    metrics_inc(METRICS_INGRESS_ROGUE_DNS);
    return 1;
  }

  int ret = lookup_dns_id(pod_key, skb);
  if (ret != 0) {
    metrics_inc(METRICS_INGRESS_TXID_MISMATCH);
    return 1;
  }

  struct event *ev;
  ev = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
  if (!ev) {
    return 1;
  }

  ev->pod_key = key_for_addr(ip->daddr);
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

SEC("cgroup_skb/egress")
int egress(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct iphdr *ip = (data);
  if (data + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end) {
    return 1;
  }

  // check if pod is subject to egress policies
  __be32 pod_key = key_for_addr(ip->saddr);
  __u32 *inner_map = bpf_map_lookup_elem(&pod_config, &pod_key);
  if (inner_map == NULL) {
    return 1;
  }

  // pass traffic if destination is upstream dns server
  __u32 dnsk = 1;
  __u32 *dns_upstream_addr = bpf_map_lookup_elem(&dns_config, &dnsk);
  if (dns_upstream_addr == NULL) {
    return 1;
  }
  if (ip->daddr == *dns_upstream_addr) {
    store_dns_id(pod_key, skb);
    metrics_inc(METRICS_EGRESS_DNS);
    return 1;
  }

  bpf_printk("pod is subject to egress filter key=%d addr=%d", pod_key,
             ip->saddr);

  __u8 *allowed = bpf_map_lookup_elem(inner_map, &ip->daddr);
  if (allowed == NULL) {
    metrics_inc(METRICS_EGRESS_BLOCKED);
    bpf_printk("no value for ip %d in inner map, blocking", ip->daddr);
    return 0;
  }
  // block
  if (*allowed == TC_BLOCK) {
    bpf_printk("blocking %d", ip->daddr);
    metrics_inc(METRICS_EGRESS_BLOCKED);
    return 0;
  }
  // allow
  else if (*allowed == TC_ALLOW) {
    bpf_printk("allowing %d", ip->daddr);
    metrics_inc(METRICS_EGRESS_ALLOWED);
    return 1;
  }
  return 1;
}

char __license[] SEC("license") = "Dual MIT/GPL";
