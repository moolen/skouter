# e2e / load tests

## Setup

- the e2e tests assume that there is a cluster with skouter running
- k6 is used as load testing tool to simulate client application behaviour
- coredns is used in a test environment to answer DNS queries from services under test
- go-httpbin is used as test upstream endpoint

## Scenarios

- functional testing
  - is allowed hostname
  - is blocked hostname
  - is not able to send queries to other DNS servers
  - state persists after re-rollout
  - audit mode
  - block host-level traffic
  - host-level traffic blocking does not affect pods
- long running tcp connections
- load testing
