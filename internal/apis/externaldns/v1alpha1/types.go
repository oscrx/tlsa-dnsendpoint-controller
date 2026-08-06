// Package v1alpha1 contains a minimal, hand-written copy of the external-dns
// DNSEndpoint API (externaldns.k8s.io/v1alpha1).
//
// We deliberately do not import sigs.k8s.io/external-dns: that module pulls in
// the SDKs for every supported DNS provider, which would add hundreds of
// transitive dependencies for the sake of two structs. The JSON shape here must
// stay compatible with the upstream CRD:
// https://github.com/kubernetes-sigs/external-dns/blob/master/config/crd/standard/dnsendpoints.externaldns.k8s.io.yaml
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	// GroupName is the API group of the DNSEndpoint CRD.
	GroupName = "externaldns.k8s.io"
	// DNSEndpointKind is the kind name for DNSEndpoint resources.
	DNSEndpointKind = "DNSEndpoint"
)

var (
	// GroupVersion is the group version used to register these objects.
	GroupVersion = schema.GroupVersion{Group: GroupName, Version: "v1alpha1"}

	// SchemeBuilder is used to add these types to a runtime.Scheme.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func addKnownTypes(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion, &DNSEndpoint{}, &DNSEndpointList{})
	metav1.AddToGroupVersion(s, GroupVersion)
	return nil
}

// ProviderSpecificProperty holds a provider-specific key/value pair. We never
// set these ourselves, but they are round-tripped so that we do not clobber
// values a user has added by hand.
type ProviderSpecificProperty struct {
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`
}

// Endpoint is a single DNS record as understood by external-dns.
type Endpoint struct {
	// DNSName is the record name, e.g. "_25._tcp.mail.example.com".
	DNSName string `json:"dnsName,omitempty"`
	// Targets holds the record data. For TLSA these are presentation-format
	// rdata strings, e.g. "3 1 1 abc123...".
	Targets []string `json:"targets,omitempty"`
	// RecordType is the DNS record type, e.g. "TLSA".
	RecordType string `json:"recordType,omitempty"`
	// SetIdentifier identifies a record set for providers that support
	// weighted/geo routing. Unused here.
	SetIdentifier string `json:"setIdentifier,omitempty"`
	// RecordTTL is the record TTL in seconds. Zero means "provider default".
	RecordTTL int64 `json:"recordTTL,omitempty"`
	// Labels carries external-dns bookkeeping.
	Labels map[string]string `json:"labels,omitempty"`
	// ProviderSpecific carries provider-specific configuration.
	ProviderSpecific []ProviderSpecificProperty `json:"providerSpecific,omitempty"`
}

// DNSEndpointSpec is the desired state of a DNSEndpoint.
type DNSEndpointSpec struct {
	Endpoints []*Endpoint `json:"endpoints,omitempty"`
}

// DNSEndpointStatus is the observed state of a DNSEndpoint, written by
// external-dns.
type DNSEndpointStatus struct {
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// DNSEndpoint is the CRD external-dns reads when its "crd" source is enabled.
type DNSEndpoint struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DNSEndpointSpec   `json:"spec,omitempty"`
	Status DNSEndpointStatus `json:"status,omitempty"`
}

// DNSEndpointList is a list of DNSEndpoint objects.
type DNSEndpointList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DNSEndpoint `json:"items"`
}

// DeepCopyInto copies the receiver into out.
func (in *ProviderSpecificProperty) DeepCopyInto(out *ProviderSpecificProperty) {
	*out = *in
}

// DeepCopy returns a deep copy of the receiver.
func (in *ProviderSpecificProperty) DeepCopy() *ProviderSpecificProperty {
	if in == nil {
		return nil
	}
	out := new(ProviderSpecificProperty)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies the receiver into out.
func (in *Endpoint) DeepCopyInto(out *Endpoint) {
	*out = *in
	if in.Targets != nil {
		out.Targets = make([]string, len(in.Targets))
		copy(out.Targets, in.Targets)
	}
	if in.Labels != nil {
		out.Labels = make(map[string]string, len(in.Labels))
		for k, v := range in.Labels {
			out.Labels[k] = v
		}
	}
	if in.ProviderSpecific != nil {
		out.ProviderSpecific = make([]ProviderSpecificProperty, len(in.ProviderSpecific))
		copy(out.ProviderSpecific, in.ProviderSpecific)
	}
}

// DeepCopy returns a deep copy of the receiver.
func (in *Endpoint) DeepCopy() *Endpoint {
	if in == nil {
		return nil
	}
	out := new(Endpoint)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies the receiver into out.
func (in *DNSEndpointSpec) DeepCopyInto(out *DNSEndpointSpec) {
	*out = *in
	if in.Endpoints != nil {
		out.Endpoints = make([]*Endpoint, len(in.Endpoints))
		for i, ep := range in.Endpoints {
			out.Endpoints[i] = ep.DeepCopy()
		}
	}
}

// DeepCopy returns a deep copy of the receiver.
func (in *DNSEndpointSpec) DeepCopy() *DNSEndpointSpec {
	if in == nil {
		return nil
	}
	out := new(DNSEndpointSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies the receiver into out.
func (in *DNSEndpointStatus) DeepCopyInto(out *DNSEndpointStatus) {
	*out = *in
}

// DeepCopy returns a deep copy of the receiver.
func (in *DNSEndpointStatus) DeepCopy() *DNSEndpointStatus {
	if in == nil {
		return nil
	}
	out := new(DNSEndpointStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies the receiver into out.
func (in *DNSEndpoint) DeepCopyInto(out *DNSEndpoint) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	out.Status = in.Status
}

// DeepCopy returns a deep copy of the receiver.
func (in *DNSEndpoint) DeepCopy() *DNSEndpoint {
	if in == nil {
		return nil
	}
	out := new(DNSEndpoint)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject returns a runtime.Object copy of the receiver.
func (in *DNSEndpoint) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto copies the receiver into out.
func (in *DNSEndpointList) DeepCopyInto(out *DNSEndpointList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]DNSEndpoint, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

// DeepCopy returns a deep copy of the receiver.
func (in *DNSEndpointList) DeepCopy() *DNSEndpointList {
	if in == nil {
		return nil
	}
	out := new(DNSEndpointList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject returns a runtime.Object copy of the receiver.
func (in *DNSEndpointList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}
