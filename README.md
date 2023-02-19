# Skouter

cloud-native egress proxy.

---

## Overview

![overview](overview.png)

## Rationale

This is a counter-draft to the traditional centralized egress firewall approach.

Requirements:

- provide a **DNS-based firewall** to allow/deny egress traffic
- **no change of existing applications needed**: an app must not rely on `HTTP_PROXY` env variables or iptables traffic redirection
- **no central infrastructure** for egress filtering: No single point of failure. Eliminate complexity introduced by HA architecture like leader election, state replication, snapshots for DR, VRRP.
- is capable of filtering **host** egress traffic
- supports audit mode that allows to discover traffic patterns before blocking them

It runs on the tc egress hook. Essentially, all traffic from the host that goes through that interface is subject to egress policies.
It parses the DNS response packets from the trusted DNS server and allows/blocks traffic egressing from the system.

There are other implemenatation approaches for egress filtering:

- L7: HTTP Proxy
- L7|L4: HTTP(S) CONNECT
- L5+: TLS SNI
- L3|L4: IP CIDRs + ports
- K8s Operator like https://github.com/giantswarm/dns-network-policy-operator

### Limitations and edge cases

* DNS over TCP is not yet supported but possible
* IPv6 is not yet supported but possible
* depending on the CNI implementation, pods may also be subject to the same egress policies as the host (overlay networking)

## Further improvements

- [ ] ~~implement DNS parsing in eBPF (beware, there be dragons!)~~ This is completely nuts
- [x] validate kube-dns source/dest IP for DNS lookups
- [x] track source port/id of DNS query and match it with response (make spoofing harder)
- [ ] support DNS over TCP
- [x] support CNAME records
- [x] packet-level metrics
- [x] regex hostnames
- [ ] support IPv6
- [x] block host traffic
- [x] support plain IPs
- [x] support IP cidr ranges
- [x] audit mode (allow egress by default but log/store traffic patterns)
- [x] clean up deleted IPs
- [x] drop initial DNS answer and respond from userspace
- [x] ~~lift limitation of 256 adresses per node~~
- [ ] instead of relying on regex use [cilium/matchpattern](https://github.com/cilium/cilium/blob/master/pkg/fqdn/matchpattern/matchpattern.go) package
- [ ] support multiple trusted upstream server
- [ ] pod traffic may be subject to redirect
- [ ] consider pivoting into making this a central egress infrastructure by ip forwarding ip packets while still supporting kubernetes integration

## Example

Given this egress config:

```yaml
apiVersion: egress.skouter/v1alpha1
kind: Egress
metadata:
  name: example
spec:
  # use nodeSelector to set up
  # host firewall
  nodeSelector: {}
  rules:
    - domains:
      - example.com
      - httpbin.org
    - ips:
      - 1.2.3.4
      - 5.7.3.1
    - cidrs:
      - 127.0.0.1/8
      - 10.0.10.0/24
    - regex:
      - .*\.wikipedia\.org # de|en|...
```

On the host system, try make HTTP calls to verify the behaviour:

```shell
% wget -O - example.com
Connecting to example.com (93.184.216.34:80)
writing to stdout
<!doctype html>
<html>
<head>
    <title>Example Domain</title>
[...]

% wget -O - github.com --timeout 5
Connecting to github.com (140.82.121.3:80)
wget: download timed out
```
