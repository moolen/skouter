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
	PodSelector PodSelector  `json:"podSelector"`
	Rules       []EgressRule `json:"rules,omitempty"`
}

type PodSelector struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
}

type EgressRule struct {
	Domains []string `json:"domains"`
	Ports   []uint32 `json:"ports"`
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
