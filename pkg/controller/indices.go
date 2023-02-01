package bpf

import (
	"bytes"
	"encoding/gob"
	"net"
	"regexp"
)

func init() {
	gob.Register(map[string]interface{}{})
}

type AddressIndex map[uint32]map[uint32]uint32

func (idx AddressIndex) Clone() AddressIndex {
	dc, _ := deepcopy(idx)
	return dc
}

type HostIndex map[string]map[uint32]struct{}

func (idx HostIndex) Clone() HostIndex {
	dc, _ := deepcopy(idx)
	return dc
}

type CIDRIndex map[uint32]map[string]*net.IPNet

func (idx CIDRIndex) Clone() CIDRIndex {
	dc, _ := deepcopy(idx)
	return dc
}

type RuleIndex map[uint32]map[string]*regexp.Regexp

func (idx RuleIndex) Clone() RuleIndex {
	dc, _ := deepcopy(idx)
	return dc
}

// Map performs a deep copy of the given map m.
func deepcopy[T interface{}](m T) (T, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	dec := gob.NewDecoder(&buf)
	err := enc.Encode(m)
	if err != nil {
		return m, err
	}
	var copy T
	err = dec.Decode(&copy)
	if err != nil {
		return m, err
	}
	return copy, nil
}
