package nais_io_v1_test

import (
	"reflect"
	"testing"

	stsv1 "github.com/nais/sts-operator/api/nais.io/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestOAuthClientScheme(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := stsv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		kind string
		obj  runtime.Object
	}{
		{kind: "OAuthClient", obj: &stsv1.OAuthClient{}},
		{kind: "OAuthClientList", obj: &stsv1.OAuthClientList{}},
	} {
		t.Run(tt.kind, func(t *testing.T) {
			gvk := stsv1.GroupVersion.WithKind(tt.kind)
			obj, err := scheme.New(gvk)
			if err != nil {
				t.Fatal(err)
			}
			if reflect.TypeOf(obj) != reflect.TypeOf(tt.obj) {
				t.Fatalf("scheme.New(%v) = %T, want %T", gvk, obj, tt.obj)
			}
			kinds, _, err := scheme.ObjectKinds(tt.obj)
			if err != nil {
				t.Fatal(err)
			}
			if len(kinds) != 1 || kinds[0] != gvk {
				t.Fatalf("ObjectKinds(%T) = %v, want [%v]", tt.obj, kinds, gvk)
			}
		})
	}
}
