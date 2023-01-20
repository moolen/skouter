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

  // do not pin right now, this causes
  // too many issues when developing/restarting
  // b/c the controller does not reconile
  // TODO: re-enable later once stabilized
  __uint(pinning, LIBBPF_PIN_BY_NAME);
  __array(values, struct pod_egress_config);
} pod_config SEC(".maps");

__u32 key_for_addr(__u32 addr) { return bpf_ntohl(addr) % 255; }

SEC("cgroup_skb/ingress")
int capture_packets(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  const __u8 dns_offset = sizeof(struct iphdr) + sizeof(struct udphdr);

  // struct ethhdr *eth = data;
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

  __be32 pod_key = key_for_addr(ip->daddr);
  __u32 *inner_map = bpf_map_lookup_elem(&pod_config, &pod_key);
  if (inner_map == NULL) {
    bpf_printk("no pod config");
    return 1;
  }
  __u32 zero = 0;
  __u32 *dns_upstream_addr = bpf_map_lookup_elem(inner_map, &zero);
  if (dns_upstream_addr == NULL) {
    bpf_printk("no value for ip %d in inner map, blocking", ip->daddr);
    return 0;
  }

  if (ip->saddr != *dns_upstream_addr) {
    bpf_printk("DNS packet not from trusted source saddr=%d", ip->saddr);
    return 0;
  }

  // TODO: verify DNS ID

  struct event *ev;
  ev = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
  if (!ev) {
    return 0;
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
  // - parse DNS packet header & only forward DNS responses
  // - verify DNS response source addr (coming from kube-system/kube-dns
  // services)
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

  __be32 pod_key = key_for_addr(ip->saddr);
  __u32 *inner_map = bpf_map_lookup_elem(&pod_config, &pod_key);
  if (inner_map == NULL) {
    // case: this pod is not subject to egress policies2
    return 1;
  }

  bpf_printk("pod is subject to egress filter key=%d addr=%d", pod_key,
             ip->saddr);

  __u8 *allowed = bpf_map_lookup_elem(inner_map, &ip->daddr);
  if (allowed == NULL) {
    bpf_printk("no value for ip %d in inner map, blocking", ip->daddr);
    return 0;
  }
  // block
  if (*allowed == TC_BLOCK) {
    bpf_printk("blocking %d", ip->daddr);
    return 0;
  }
  // allow
  else if (*allowed == TC_ALLOW) {
    bpf_printk("allowing %d", ip->daddr);
    return 1;
  }
  return 1;
}

char __license[] SEC("license") = "Dual MIT/GPL";
