package nais_io_v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(GroupVersion, &OAuthImpersonation{}, &OAuthImpersonationList{})
		return nil
	})
}

// +genclient
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Created",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="Synced",type="date",JSONPath=".status.synchronizationTimestamp"
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// OAuthImpersonation allows subjects to impersonate the OAuthClient with the same name.
type OAuthImpersonation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OAuthImpersonationSpec   `json:"spec"`
	Status OAuthImpersonationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OAuthImpersonationList contains a list of OAuthImpersonation.
type OAuthImpersonationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OAuthImpersonation `json:"items"`
}

type OAuthImpersonationSpec struct {
	// AllowedSubjects are the subjects allowed to impersonate the client.
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:items:MinLength=1
	AllowedSubjects []string `json:"allowedSubjects"`
}

// ObservedImpersonation identifies a version of an OAuthImpersonation.
type ObservedImpersonation struct {
	UID        types.UID `json:"uid"`
	Generation int64     `json:"generation"`
}

// OAuthImpersonationStatus defines the observed state of OAuthImpersonation.
type OAuthImpersonationStatus struct {
	// SynchronizationTimestamp is the time of the last successful reconciliation.
	// +optional
	SynchronizationTimestamp *metav1.Time `json:"synchronizationTimestamp,omitempty"`
	// Conditions describe the observed state. Ready reports the outcome of the
	// last reconciliation; it applies to the current spec only when its
	// observedGeneration matches metadata.generation.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}
