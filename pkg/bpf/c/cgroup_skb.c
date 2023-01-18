#include "headers/common.h"
#include "headers/dns.h"
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

// == host_config ==
// lookup pod ip => hostname

// host_key_t contains the hostname which is used to lookup
// when analyzing DNS responses
struct host_key_t {
  __u8 hostname[MAX_QNAME_LEN];
};

// Force emitting struct event into the ELF so we can use it in go
const struct host_key_t *unused2 __attribute__((unused));

// nested inner map to lookup destination hostname => host policy setting
struct host_egress_config {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_IP_ENTRIES);
  __type(key, struct host_key_t); // dest hostname
  __type(value, __u32);           // nothing, yet
};

// nested outer map to lookup pod ip -> (hostname=>host policy setting)
struct {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, MAX_IP_ENTRIES);
  __type(key, __u32); // pod IPv4 address
  __uint(pinning, LIBBPF_PIN_BY_NAME);
  __array(values, struct host_egress_config);
} host_config SEC(".maps");

// kernel-allocated map to store hostname
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct host_key_t);
} alloc_hostname SEC(".maps");

// simple wrapper for skb
struct cursor {
  void *pos;
  void *end;
};

static __inline void cursor_init_skb(struct cursor *c, struct __sk_buff *skb) {
  c->end = (void *)(long)skb->data_end;
  c->pos = (void *)(long)skb->data;
}

// data_t is used to store the in-flight DNS response data
// TODO: allocate this in kernel space
struct data_t {
  __u16 q_section_len;
  __u16 qname_ptr[MAX_ANS_COUNT];
  __u32 qname_addr[MAX_ANS_ADDR];
  __u8 qname_count;
};

// takes a packet cursor which must point to the first byte of a answer section
// this function parses the answer and writes the hostname pointer and address
// into _data. WARNING: only a limited number of answers are supported
// (MAX_ANS_COUNT). returns 0 on success, negative otherwise.
__always_inline int read_answers(struct cursor *c, struct dnshdr *dns,
                                 struct data_t *_data) {
  unsigned short ans_cnt = bpf_ntohs(dns->ans_count);
  __u16 ans_offset = -1;
  for (__u8 i = 0; i < MAX_ANS_COUNT; i++) {
    __u8 val;
    if (ans_cnt == 0) {
      break;
    }
    c->pos++;
    ans_offset++;
    if (c->pos + 1 > c->end) {
      bpf_printk("answer reached end. breaking at %d", i);
      return -1;
    }
    val = *(__u8 *)c->pos;

    bpf_printk("[%i] ans: %d", i, val);

    // we start with either a pointer to a qname (0xC0)
    // or with the number of bytes following that define a label

    // handle non-ptr
    if (val != 0xC0) {
      bpf_printk("found non-ptr, i=%d advancing=%d offset=%d", i, val, _data->q_section_len);

      // store position of qname
      _data->qname_ptr[_data->qname_count & 10] =
          _data->q_section_len + ans_offset;
      _data->qname_count++;

      // advance forward
      c->pos += val;

      // skip labels
      for (int j = 0; j < MAX_LABELS; j++) {
        if (c->pos + 1 > c->end) {
          bpf_printk("answer ptr reached end. breaking at %d/%d", i, j);
          return -1;
        }
        val = *(__u8 *)c->pos;
        if (val == 0x0) {
          break;
        }
        bpf_printk("ans: advancing %d", val);
        c->pos += val;
      }
      // move to next byte, this should be the type
      c->pos++;
    } else {
      // handle ptr
      c->pos++;
      if (c->pos + 1 > c->end) {
        return -1;
      }
      _data->qname_ptr[_data->qname_count & 10] = *(__u8 *)c->pos;
      _data->qname_count++;
      c->pos += 2; // move to 'type' 0x28=AAAA; 0x01=A
    }

    if (c->pos + 1 > c->end) {
      return -1;
    }
    __u8 tp = (*(__u8 *)c->pos);
    if (tp != 0x01) {
      return -1;
    }

    c->pos += 7; // move to 'RDLENGTH'
    if (c->pos + 2 > c->end) {
      return -1;
    }
    // TODO: support ipv6
    __u16 len = bpf_ntohs(*(__u16 *)c->pos);
    if (len != 4) {
      return -1;
    }
    c->pos += 2; // move to address
    if (c->pos + 4 > c->end) {
      return -1;
    }
    __u32 addr = *(__u32 *)c->pos;
    _data->qname_addr[0] = addr;

    c->pos += 4; // skip address, move to next ans or end
    ans_cnt--;
  }
  return 0;
}

// moves the packet cursor `c` forward by skipping all question sections
// Takes a cursor which must point to the first byte _after_ the dns header.
// Also takes a dns header that contains the number of questions in the given
// packet. returns 0 on success, negative otherwise.
__always_inline int skip_questions(struct cursor *c, struct dnshdr *dns,
                                   struct data_t *_data) {
  unsigned short q_count = bpf_ntohs(dns->q_count);
  __u16 q_sec_len = 0;
  for (__u8 i = 0; i < MAX_LABELS; i++) {
    __u8 val;
    if (q_count == 0) {
      bpf_printk("skipping question count");
      break;
    }
    c->pos++;
    q_sec_len++;
    if (c->pos + 1 > c->end) {
      bpf_printk("q: end of packet");
      return -1;
    }
    val = *(__u8 *)c->pos;
    bpf_printk("q: %d", val);
    // we start with either a pointer to a qname
    // or with the number of bytes following that define a label
    if (val == 0xC0) {
      c->pos += 2;
      q_sec_len += 2;
      bpf_printk("q: break ptr");
      break;
    } else {
      c->pos += val;
      q_sec_len += val;
    }

    // end of label
    // continue with next section
    if (val == 0x00) {
      bpf_printk("q: end of label");
      // skip next 4 bytes: 2 type field (A/AAAA) + 2 class field
      c->pos += 4;
      q_sec_len += 4;
      q_count--;
    }
  }

  _data->q_section_len = q_sec_len;
  return 0;
};

// reads the hostname at the given cursor position
// and writes it into `qname`. This function will always append a trailing .
// We do not recurse if we encounter a pointer to a different section in the
// packet. Returns the hostname string length
__always_inline int read_qname(struct cursor *c, char qname[MAX_QNAME_LEN]) {
  c->pos--;
  int qname_cursor = 0;
  int label_to_parse = 0;
  for (int i = 0; i < MAX_QNAME_LEN; i++) {
    __u8 val;
    c->pos++;
    if (c->pos + 1 > c->end) {
      return -1;
    }
    val = *(__u8 *)c->pos;

    // we don't like ptr; bail out
    if (val == 0xC0) {
      return -1;
    }
    // we're done
    if (val == 0x00) {
      break;
    }
    if (label_to_parse == 0) {
      label_to_parse = val;
      if (i != 0) {
        qname[qname_cursor] = '.';
        qname_cursor++;
      }
      continue;
    }
    qname[qname_cursor] = val;
    qname_cursor++;
    label_to_parse--;
  }
  qname[qname_cursor] = '.';
  qname_cursor++;
  qname[qname_cursor] = 0;
  return qname_cursor;
}

__u32 key_for_addr(__u32 addr) { return bpf_ntohl(addr) % 255; }

// parses the incoming DNS response packet
// - reads from host_config to see if the DNS response is destined for a pod
// - verifies that the response host is legitimate by comparing with an
// allowlist
// - writes the address of hostname to pod_config so packets will be allowed to
// egress
SEC("cgroup_skb/ingress") int ingress(struct __sk_buff *skb) {
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
    return 1;
  }

  if (udp->source != PORT_DNS && udp->dest != PORT_DNS) {
    return 1;
  }

  // skip unmanaged pods
  __be32 outer_key = key_for_addr(ip->daddr);
  __u32 *inner_map = bpf_map_lookup_elem(&host_config, &outer_key);
  if (inner_map == NULL) {
    // case: unmanaged pod
    bpf_printk("could not find host config for %d", outer_key);
    return 1;
  }

  bpf_printk("saddr=%lu daddr=%lu outer_key=%lu qcount=%d acount=%d", ip->saddr,
             ip->daddr, outer_key, dns->q_count, dns->ans_count);

  // dump packet
  struct cursor c;
  cursor_init_skb(&c, skb);
  c.pos += dns_offset + sizeof(struct dnshdr);

  __u8 off = 36;
  c.pos +=off;
  for (__u8 i=off; i<off+12; i++) {
    if(c.pos+1 > c.end){
      return 1;
    }
    bpf_printk("[%x] = %x", i, *(__u8 *)c.pos);
    c.pos++;
  }

  // end dump packet
  struct data_t _data = {0};
  cursor_init_skb(&c, skb);
  c.pos += dns_offset + sizeof(struct dnshdr) - 1;


  bpf_printk("c.pos=%lu c.end=%lu", c.pos, c.end);
  skip_questions(&c, dns, &_data);
  bpf_printk("c.pos=%lu before answer", c.pos);
  read_answers(&c, dns, &_data);
  bpf_printk("c.pos=%lu after answer", c.pos);

  bpf_printk("qname=%s", _data.qname_ptr);

  if (_data.qname_count != 1) {
    return 1;
  }

  // position in the packet where the name starts
  __u8 ptr = _data.qname_ptr[0];
  c.pos = (void *)data + dns_offset + ptr;
  char qname[MAX_QNAME_LEN] = {0};
  int qname_len = read_qname(&c, qname);
  if (qname_len < 0) {
    bpf_printk("cannot read qname ret=%d", qname_len);
    return 1;
  }

  bpf_printk("qname=%s", qname);

  __u32 zero = 0;
  struct host_key_t *inner_key = bpf_map_lookup_elem(&alloc_hostname, &zero);
  if (!inner_key) {
    bpf_printk("could not alloc hostname");
    return 1;
  }

  for (int i = 0; i < qname_len; i++) {
    inner_key->hostname[i] = qname[i];
  }

  // check if the hostname exists in the map
  // if it does: update pod_config to allow egress traffic towards it
  __u8 *host_matches = bpf_map_lookup_elem(inner_map, inner_key);
  if (host_matches != NULL) {
    bpf_printk("found hostname=%s", inner_key->hostname);
    __u32 *inner_map = bpf_map_lookup_elem(&pod_config, &outer_key);
    if (inner_map == NULL) {
      bpf_printk("couldn't find pod config");
      goto end;
    }

    // allow egress
    bpf_printk("allowing addr=%d", _data.qname_addr[0]);
    __u8 ok = TC_ALLOW;
    bpf_map_update_elem(inner_map, &_data.qname_addr[0], &ok, BPF_ANY);
  } else {
    bpf_printk("no value for host=%s", inner_key->hostname);
  }

end:
  // zero out
  for (int i = 0; i < MAX_QNAME_LEN; i++) {
    inner_key->hostname[i] = 0;
  }

  return 1;
}

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

  __be32 outer_key = key_for_addr(ip->daddr);
  __u32 *inner_map = bpf_map_lookup_elem(&pod_config, &outer_key);
  if (inner_map == NULL) {
    bpf_printk("no pod config");
    return 1;
  }

  bpf_printk("sending to ringbuf");

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

  // struct ethhdr *eth = data;
  struct iphdr *ip = (data);
  struct udphdr *udp = (data + sizeof(struct iphdr));

  if (data + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end) {
    return 1;
  }

  // TODO:
  // - verify DNS destination addr matches kube-system/kube-dns service
  if (ip->protocol == PROTO_UDP && udp->dest == PORT_DNS) {
    bpf_printk("skipping initial dns query dst=%lu src=%lu", ip->daddr,
               ip->saddr);
    return 1;
  }

  __be32 outer_key = key_for_addr(ip->saddr);
  // bpf_printk("saddr=%lu daddr=%lu outer_key=%lu", ip->saddr, ip->daddr,
  //            outer_key);
  __u32 *inner_map = bpf_map_lookup_elem(&pod_config, &outer_key);
  if (inner_map == NULL) {
    // case: this pod is not subject to egress policies
    return 1;
  }

  bpf_printk("pod is subject to egress filter key=%d addr=%d", outer_key,
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
