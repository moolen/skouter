#include "headers/common.h"

#define PROTO_UDP 17
#define PROTO_TCP 6
#define PORT_DNS 13568 // htons(53)

#define MAX_IP_ENTRIES 512
#define MAX_EGRESS_IPS 4096
#define MAX_EGRESS_CIDRS 256
#define MAX_PKT 768

#define TC_ALLOW 1
#define TC_BLOCK 2

#define ETH_HLEN 14
#define ETH_ALEN 6
#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define L4_PORT_OFF                                                            \
  (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, dest))
#define UDP_CSUM_OFF                                                           \
  (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, check))
#define TCP_CSUM_OFF                                                           \
  (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))

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

struct dns_server_endpoint {
  __u32 addr;
  __u16 port;
};

const struct dns_server_endpoint *unused __attribute__((unused));

// map to store the upstream dns server address
// this is used to verify the dst address (egress) or
// src address (ingress).
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_IP_ENTRIES);
  __type(key, __u32);   // upstream dns server address
  __type(value, __u16); // dest port
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} dns_config SEC(".maps");

struct proxy_redirect_config {
  __u32 addr;
  __u16 ifindex;
};

const struct proxy_redirect_config *unused3 __attribute__((unused));

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, sizeof(struct proxy_redirect_config));
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} proxy_redirect_map SEC(".maps");

struct proxy_redirect_dmac {
  __u8 dmac[6];
  __u16 unused;
};

const struct proxy_redirect_dmac *unused4 __attribute__((unused));

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, sizeof(struct proxy_redirect_dmac));
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} proxy_redirect_dmac_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 2048); // size of connection pool
  __type(key, __u64);
  __type(value, __u32);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} proxy_socket_cookie SEC(".maps");

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

struct redirect_data {
  __u32 orig_saddr;
  __u32 orig_daddr;
  __u16 orig_dport;
  __u16 new_dport;
  __u8 protocol;
};

long redirect_proxy(struct __sk_buff *skb, struct redirect_data *rr) {
  if (rr == NULL) {
    return TC_ALLOW;
  }
  __u32 pkey = 0;
  struct proxy_redirect_config *proxy_cfg =
      bpf_map_lookup_elem(&proxy_redirect_map, &pkey);
  if (proxy_cfg == NULL) {
    return TC_ALLOW;
  }

  // TODO: replace this with fib_lookup if possible
  struct proxy_redirect_dmac *dmac_cfg =
      bpf_map_lookup_elem(&proxy_redirect_dmac_map, &pkey);
  if (dmac_cfg == NULL) {
    return TC_ALLOW;
  }

  int ret = bpf_skb_store_bytes(skb, 0, &dmac_cfg->dmac, sizeof(dmac_cfg->dmac),
                                0);
  ret = bpf_skb_store_bytes(skb, 6, &dmac_cfg->dmac, sizeof(dmac_cfg->dmac),
                                0);
  if (ret != 0) {
    return -1;
  }

	// __be32 sum;
	// sum = bpf_csum_diff(&rr->orig_daddr, sizeof(__u32), &proxy_cfg->addr,
	// 		sizeof(proxy_cfg->addr), 0);
	// if (bpf_skb_store_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr),
	//     &proxy_cfg->addr, sizeof(proxy_cfg->addr), 0) < 0) {
	// 	return -1;
	// }
	// if (bpf_l3_csum_replace(skb, ETH_HLEN + offsetof(struct iphdr, check),
	//     0, sum, 0) < 0) {
	// 	return -1;
	// }

	// sum = bpf_csum_diff(&rr->orig_dport, sizeof(__u16), &rr->new_dport,
	// 		sizeof(rr->new_dport), 0);
	// if (bpf_skb_store_bytes(skb, ETH_HLEN + offsetof(struct iphdr, saddr),
	//     &tunnel_source, sizeof(tunnel_source), 0) < 0) {
	// 	ret = DROP_WRITE_ERROR;
	// 	goto drop_err;
	// }
	// if (bpf_l3_csum_replace(skb, ETH_HLEN + offsetof(struct iphdr, check),
	//     0, sum, 0) < 0) {
	// 	ret = DROP_CSUM_L3;
	// 	goto drop_err;
	// }

  __u32 l4_csum_offset = UDP_CSUM_OFF;
  switch (rr->protocol) {
  case PROTO_UDP:
    l4_csum_offset = UDP_CSUM_OFF;
    break;
  case PROTO_TCP:
    l4_csum_offset = TCP_CSUM_OFF;
    break;
  }

  // set dst port
  bpf_l4_csum_replace(skb, l4_csum_offset, rr->orig_dport, rr->new_dport,
                      sizeof(__u16));
  ret = bpf_skb_store_bytes(skb, L4_PORT_OFF, &rr->new_dport,
                            sizeof(rr->new_dport), 0);
  if (ret != 0) {
    return -1;
  }

  // set src
  //bpf_l3_csum_replace(skb, IP_CSUM_OFF, rr->orig_saddr, rr->orig_saddr,
  //                     sizeof(__u16));
  bpf_skb_store_bytes(skb, IP_SRC_OFF, &rr->orig_daddr, sizeof(__u32),
                       0);

  // set dst
  //bpf_l3_csum_replace(skb, IP_CSUM_OFF, rr->orig_daddr, proxy_cfg->addr,
  //                    sizeof(__u16));
  ret = bpf_skb_store_bytes(skb, IP_DST_OFF, &proxy_cfg->addr, sizeof(__u32),
                            0);
  if (ret != 0) {
    return -1;
  }

  return bpf_redirect(proxy_cfg->ifindex, BPF_F_INGRESS);
}

SEC("classifier/cls")
int ingress(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct iphdr *ip = (data + sizeof(struct ethhdr));
  struct udphdr *udp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
          sizeof(struct udphdr) >
      data_end) {
    return TC_ACT_OK;
  }

  if (udp->dest == PORT_DNS) {
    bpf_printk("ingress DNS saddr=%lu daddr=%lu", ip->saddr, ip->daddr);
  }

  return TC_ACT_OK;
}

SEC("classifier/cls")
int classifier(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct iphdr *ip = (data + sizeof(struct ethhdr));
  struct udphdr *udp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
          sizeof(struct udphdr) >
      data_end) {
    return TC_ACT_OK;
  }

  if (udp->dest == PORT_DNS) {
    bpf_printk("egress DNS saddr=%lu daddr=%lu", ip->saddr, ip->daddr);
  }

  // check if packet originated from dnsproxy
  // this is trusted and shall be forwarded in any case
  __u64 cookie = bpf_get_socket_cookie(skb);
  __u32 *match = bpf_map_lookup_elem(&proxy_socket_cookie, &cookie);
  if (match != NULL) {
    return TC_ACT_OK;
  }

  // TMP: allow marked traffic
  if ((skb->mark & 0xb00) == 0xb00) {
    return TC_ACT_OK;
  }

  // check if source is subject to policies
  // if not: pass;
  __u32 *inner_map = bpf_map_lookup_elem(&egress_config, &ip->saddr);
  if (inner_map == NULL) {
    return TC_ACT_OK;
  }

  // check if this is the trusted dns endpoint.
  // if so: redirect traffic back to userspace
  __u16 *dst_port = bpf_map_lookup_elem(&dns_config, &ip->daddr);
  if (dst_port != NULL) {

    struct redirect_data rr = {0};
    rr.orig_saddr = ip->saddr;
    rr.orig_daddr = ip->daddr;
    rr.orig_dport = udp->dest;
    rr.new_dport = *dst_port;
    rr.protocol = ip->protocol;
    long ret = redirect_proxy(skb, &rr);
    bpf_printk("redirect mark=%d ret=%d", skb->mark, ret);
    return ret;
  }

  // apply firewall rules
  if (egress_ip_allowed(ip->saddr, ip->daddr) == TC_BLOCK &&
      egress_cidr_allowed(ip->saddr, ip->daddr) == TC_BLOCK) {
    return TC_ACT_SHOT;
  }
  return TC_ALLOW;
}

char __license[] SEC("license") = "Dual MIT/GPL";
