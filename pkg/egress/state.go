package egress

import (
	"sync"

	v1alpha1 "github.com/moolen/skouter/api"
)

type EgressState struct {
	data map[string]*v1alpha1.Egress
	lock *sync.Mutex
}

func NewEgressState() *EgressState {
	return &EgressState{
		data: make(map[string]*v1alpha1.Egress),
		lock: &sync.Mutex{},
	}
}

func (e *EgressState) Set(key string, val *v1alpha1.Egress) {
	e.lock.Lock()
	defer e.lock.Unlock()
	e.data[key] = val
}

func (e *EgressState) Delete(key string) {
	e.lock.Lock()
	defer e.lock.Unlock()
	delete(e.data, key)
}

func (e *EgressState) HostMap() map[string]*v1alpha1.Egress {
	e.lock.Lock()
	defer e.lock.Unlock()
	m := make(map[string]*v1alpha1.Egress)
	for k, v := range e.data {
		m[k] = v.DeepCopy()
	}
	return m
}
