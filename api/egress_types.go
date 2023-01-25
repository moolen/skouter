/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,categories={egress},shortName=eg
type Egress struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EgressSpec   `json:"spec,omitempty"`
	Status EgressStatus `json:"status,omitempty"`
}

type EgressSpec struct {
	// +kubebuilder:validation:Optional
	PodSelector *Selector `json:"podSelector,omitempty"`
	// +kubebuilder:validation:Optional
	NodeSelector *Selector    `json:"nodeSelector,omitempty"`
	Rules        []EgressRule `json:"rules,omitempty"`
}

type Selector struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
}

type EgressRule struct {
	// Domains let you allow-list individual hosts
	// The IPs are resolved and allow-listed inflight.
	Domains []string `json:"domains,omitempty"`

	// IPs let you allow-list individual IPs
	// IPs are stored in a map structure, hence there is no
	// performance penalty of specifying lots of IPs.
	IPs []string `json:"ips,omitempty"`

	// CIDRs allows you to allow-list whole CIDR ranges
	// max 255 CIDRs are supported.
	CIDRs []string `json:"cidrs,omitempty"`
}

type EgressStatus struct {
	Nodes map[string]NodeStatus `json:"nodeStatus"`
}

type NodeStatus struct {
}

// +kubebuilder:object:root=true

// EgressList contains a list of Egress resources.
type EgressList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Egress `json:"items"`
}
