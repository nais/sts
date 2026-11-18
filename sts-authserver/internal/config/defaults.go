package config

import (
	"fmt"
	"reflect"

	"go.yaml.in/yaml/v3"
)

// Apply initializes zero-valued fields from default tags before decoding
// user configuration. It accepts a pointer to a struct and recurses into nested
// structs; pointers, maps, and slices are not traversed.
func Apply(target any) error {
	value := reflect.ValueOf(target).Elem()
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		if !field.CanSet() {
			continue
		}
		name := value.Type().Field(i).Name
		if text, ok := value.Type().Field(i).Tag.Lookup("default"); ok && field.IsZero() {
			node := yaml.Node{Kind: yaml.ScalarNode, Value: text}
			if err := node.Decode(field.Addr().Interface()); err != nil {
				return fmt.Errorf("field %s: %w", name, err)
			}
		}
		if field.Kind() == reflect.Struct {
			if err := Apply(field.Addr().Interface()); err != nil {
				return fmt.Errorf("field %s: %w", name, err)
			}
		}
	}
	return nil
}
