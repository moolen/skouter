#include "headers/common.h"
#include "headers/dns.h"
#include <bpf/bpf_endian.h>
#include <linux/udp.h>

#define PROTO_UDP 17
#define PORT_DNS 13568 // htons(53)
#define MAX_PKT 512

struct event {
  u8 len;
  __u32 pod_addr;
  u8 pkt[MAX_PKT];
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} events SEC(".maps");

#define MAX_IP_ENTRIES 256

struct pod_egress_config {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_IP_ENTRIES);
  __type(key, __u32);   // dest IPv4 address
  __type(value, __u32); // allowed setting
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, MAX_IP_ENTRIES);
  __type(key, __u32); // pod IPv4 address
  __uint(pinning, LIBBPF_PIN_BY_NAME);
  __array(values, struct pod_egress_config);
} pod_config SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

//
//
//
//
#define MAX_LABELS 50

struct cursor {
  void *pos;
  void *end;
};

static __inline void cursor_init_skb(struct cursor *c, struct __sk_buff *skb) {
  c->end = (void *)(long)skb->data_end;
  c->pos = (void *)(long)skb->data;
}

struct readname_rs_t {
  __u8 err;
  __u8 *labels[MAX_LABELS];
  __u8 labelcnt;
  __u8 ptr;
};

static __inline void readqname(struct cursor *c, struct readname_rs_t *rs) {
  __u8 i;

  for (i = 0; i < MAX_LABELS; i++) { /* Maximum 128 labels */
    __u8 o;

    if (c->pos + 1 > c->end) {
      bpf_printk("oob 1: %lu", c->pos);
      rs->err = 1;
      return;
    }

    // number of subsequent bytes that contain the qname
    o = *(__u8 *)c->pos;
    bpf_printk("lbl: %lx", o);
    // pointer to location in DNS paket that includes the query
    if ((o & 0xC0) == 0xC0) {
      __u8 next = *(__u8 *)c->pos + 1;
      if (c->pos + 1 > c->end) {
        bpf_printk("oob 1: %lu", c->pos);
        rs->err = 2;
        return;
      }
      bpf_printk("oob 2: pos=%lu ptr=%lu", c->pos, next);
      rs->ptr = next;
      return;

    } else if (o & 0xC0) {
      /* Unknown label type */
      bpf_printk("oob 3: 0x%lx", o);
      rs->err = 3;
      return;
    }

    rs->labels[i] = c->pos;
    rs->labelcnt++;
    c->pos += o + 1;
    if (!o)
      break;
  }
  return;
}

//
//
//
//

SEC("cgroup_skb/ingress")
int capture_packets(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  const __u8 dns_offset = sizeof(struct iphdr) + sizeof(struct udphdr);

  // struct ethhdr *eth = data;
  struct iphdr *ip = (data);
  struct udphdr *udp = (data + sizeof(struct iphdr));
  struct dnshdr *dns = (data + sizeof(struct iphdr) + sizeof(struct udphdr));

  // return early if not enough data
  if (data + dns_offset + sizeof(struct dnshdr) > data_end) {
    bpf_printk("not enough data data=%lx dns_offset=%lx end=%lx", data,
               dns_offset, data_end);
    return 1;
  }

  if (ip->protocol != PROTO_UDP) {
    // bpf_printk("no udp");
    return 1;
  }

  if (udp->source != PORT_DNS && udp->dest != PORT_DNS) {
    // bpf_printk("no dns port");
    return 1;
  }

  //
  //
  //
  //
  bpf_printk("dns response=%lu", dns->qr);
  bpf_printk("udp src: %lu dst: %lu", udp->source, udp->dest);

  struct cursor c;
  cursor_init_skb(&c, skb);

  c.pos = (data + sizeof(struct iphdr) + sizeof(struct udphdr) +
           sizeof(struct dnshdr));

  struct readname_rs_t rs = {0};
  bpf_printk("rs init err=%lu ptr=%lu", rs.err, rs.ptr);
  readqname(&c, &rs);
  bpf_printk("rs 1 err=%lu ptr=%lu lblcnt=%lu", rs.err, rs.ptr, rs.labelcnt);
  if (rs.ptr != 0) {
    bpf_printk("got ptr: %lu", rs.ptr);
    c.pos = c.pos =
        (data + sizeof(struct iphdr) + sizeof(struct udphdr)) + rs.ptr;
    readqname(&c, &rs);
    bpf_printk("rs 2 err=%lu ptr=%lu", rs.err, rs.ptr);
  }
  if (rs.err != 0) {
    bpf_printk("err readname: %lu", rs.err);
    return 1;
  }

  for (int i = 0; i < rs.labelcnt; i++) {
    __u8 o = *rs.labels[i];
    //__u8 *qname[MAX_LABELS] = {0};

    bpf_printk("outl: %c", o);

    c.pos = (data + sizeof(struct iphdr) + sizeof(struct udphdr) +
             sizeof(struct dnshdr)) +
            o;
    if (c.pos > c.end) {
      bpf_printk("outfoo 1: %lu", c.pos);
      return 1;
    }
  }

  bpf_printk("label: %s", rs.labels);
  //
  //
  //
  //

  // for the moment: ignore
  __be32 outer_key = bpf_ntohl(ip->daddr) % 255;
  __u32 *inner_map = bpf_map_lookup_elem(&pod_config, &outer_key);
  if (inner_map == NULL) {
    // bpf_printk("no pod config");
    return 1;
  }

  bpf_printk("sending to ringbuf");

  struct event *ev;
  ev = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
  if (!ev) {
    bpf_printk("ringbuf err");
    return 0;
  }

  ev->pod_addr = ip->daddr;
  for (int i = 0; i < MAX_PKT; i++) {
    if (dns_offset + i > skb->len) {
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
  bpf_printk("submit");
  bpf_ringbuf_submit(ev, 0);
  return 1;
}

SEC("cgroup_skb/egress")
int block_packets(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  // struct ethhdr *eth = data;
  struct iphdr *ip = (data);
  struct udphdr *udp = (data + sizeof(struct iphdr));

  if (data + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end) {
    return 1;
  }

  // TODO:
  // - verify DNS destination addr matches kube-system/kube-dns service
  if (ip->protocol == PROTO_UDP && udp->dest == PORT_DNS) {
    // bpf_printk("skipping initial dns query dst=%lu src=%lu", udp->dest,
    // udp->source);
    return 1;
  }

  __be32 outer_key = bpf_ntohl(ip->saddr) % 255;
  // bpf_printk("saddr=%lu daddr=%lu outer_key=%lu", ip->saddr, ip->daddr,
  // outer_key);
  __u32 *inner_map = bpf_map_lookup_elem(&pod_config, &outer_key);
  if (inner_map == NULL) {
    return 1;
  }

  __u8 *allowed = bpf_map_lookup_elem(inner_map, &ip->daddr);
  if (allowed == NULL) {
    // bpf_printk("no value for ip %d, blocking", ip->daddr);
    return 0;
  }

  // block
  if (*allowed == 2) {
    // bpf_printk("blocking %d", ip->daddr);
    return 0;
  }
  // allow
  else if (*allowed == 1) {
    // bpf_printk("allowing %d", ip->daddr);
    return 1;
  }
  return 1;
}

char __license[] SEC("license") = "Dual MIT/GPL";
