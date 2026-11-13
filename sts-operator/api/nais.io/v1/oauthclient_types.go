package nais_io_v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(GroupVersion, &OAuthClient{}, &OAuthClientList{})
		return nil
	})
}

// +genclient
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Created",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="Synced",type="date",JSONPath=".status.synchronizationTimestamp"
// +kubebuilder:printcolumn:name="Client ID",type="string",JSONPath=".status.clientID",priority=1
// +kubebuilder:printcolumn:name="ConfigMap",type="string",JSONPath=".spec.configMapName",priority=1
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// OAuthClient represents an OAuth2 client registered with STS.
type OAuthClient struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OAuthClientSpec   `json:"spec"`
	Status OAuthClientStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OAuthClientList contains a list of OAuthClient.
type OAuthClientList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OAuthClient `json:"items"`
}

type OAuthClientSpec struct {
	// ConfigMapName is the immutable name of the application ConfigMap in this namespace.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="configMapName is immutable"
	ConfigMapName string `json:"configMapName"`

	// AllowAll grants every registered client access to this client,
	// without roles. Workloads listed in the access control list still get
	// their roles.
	// +optional
	AllowAll bool `json:"allowAll,omitempty"`

	// AccessControlList grants consumers access to this client, grouped by team.
	// +listType=map
	// +listMapKey=team
	// +optional
	AccessControlList []AccessControlList `json:"acl,omitempty"`
}

// +kubebuilder:validation:AtLeastOneOf=allowAll;workloads
type AccessControlList struct {
	// Team is the consumers' namespace.
	Team string `json:"team"`
	// AllowAll grants every workload in the team access to this
	// client, without roles. Listed workloads still get their roles.
	// +optional
	AllowAll bool `json:"allowAll,omitempty"`
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MinItems=1
	// +optional
	Workloads []Workload `json:"workloads,omitempty"`
}

type Workload struct {
	// Name is the consumer's service account name.
	Name string `json:"name"`
	// Roles are added to tokens issued to the consumer for this client.
	// +listType=set
	// +optional
	Roles []Role `json:"roles,omitempty"`
}

// +kubebuilder:validation:MaxLength=255
// +kubebuilder:validation:Pattern=`^[a-z](?:[a-z0-9_./-]*[a-z0-9])?$`
type Role = string

const ConditionReady = "Ready"

const (
	ReasonSucceeded = "Succeeded"
	ReasonFailed    = "Failed"
)

// OAuthClientStatus defines the observed state of OAuthClient.
type OAuthClientStatus struct {
	// ClientID is the OAuth2 client ID most recently returned by STS.
	// +optional
	ClientID string `json:"clientID,omitempty"`
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
