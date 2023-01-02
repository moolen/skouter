package v1alpha1

import (
	"reflect"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

// Package type metadata.
const (
	Group   = "egress.skouter"
	Version = "v1alpha1"
)

var (
	// SchemeGroupVersion is group version used to register these objects.
	SchemeGroupVersion = schema.GroupVersion{Group: Group, Version: Version}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: SchemeGroupVersion}
	AddToScheme   = SchemeBuilder.AddToScheme
)

// Egress type metadata.
var (
	EgressKind             = reflect.TypeOf(Egress{}).Name()
	EgressGroupKind        = schema.GroupKind{Group: Group, Kind: EgressKind}.String()
	EgressKindAPIVersion   = EgressKind + "." + SchemeGroupVersion.String()
	EgressGroupVersionKind = SchemeGroupVersion.WithKind(EgressKind)
)

func init() {
	SchemeBuilder.Register(&Egress{}, &EgressList{})
}
