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
// +kubebuilder:printcolumn:name="Created",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="Synced",type="date",JSONPath=".status.synchronizationTimestamp"
// +kubebuilder:printcolumn:name="Client ID",type="string",JSONPath=".status.clientID",priority=1
// +kubebuilder:printcolumn:name="Secret",type="string",JSONPath=".status.synchronizationSecretName",priority=1
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

	// AccessControlList grants consumers access to this client, grouped by team.
	// +listType=map
	// +listMapKey=team
	// +optional
	AccessControlList []AccessControlList `json:"acl,omitempty"`
}

type AccessControlList struct {
	// Team is the consumers' namespace.
	Team string `json:"team"`
	// +listType=map
	// +listMapKey=name
	Workloads []Workload `json:"workloads"`
}

type Workload struct {
	// Name is the consumer's service account name.
	Name string `json:"name"`
	// Roles are added to tokens issued to the consumer for this client.
	// +listType=set
	// +optional
	Roles []string `json:"roles,omitempty"`
}

// OAuthClientStatus defines the observed state of OAuthClient.
type OAuthClientStatus struct {
	// ClientID is the OAuth2 Client ID associated with this workload
	ClientID string `json:"clientID,omitempty"`
	// ObservedGeneration is the most recent generation observed by the controller.
	// If this is equal to metadata.generation, then that means that the current reported status reflects the most recent desired state of the resource.
	ObservedGeneration       int64       `json:"observedGeneration,omitempty"`
	SynchronizationTimestamp metav1.Time `json:"synchronizationTimestamp,omitempty"`
	CorrelationID            string      `json:"correlationID,omitempty"`
	// conditions represent the current state of the controlled resource.
	// Each condition has a unique type and reflects the status of a specific aspect of the resource.
	//
	// Standard condition types include:
	// - "Available": the resource is fully functional
	// - "Progressing": the resource is being created or updated
	// - "Degraded": the resource failed to reach or maintain its desired state
	//
	// The status of each condition is one of True, False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}
