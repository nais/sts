package jwa

import "fmt"

var supportedAlgorithms = map[string]struct{}{
	"RS256": {}, "RS384": {}, "RS512": {},
	"PS256": {}, "PS384": {}, "PS512": {},
	"ES256": {}, "ES384": {}, "ES512": {},
}

func ValidateAlgorithms(algorithms ...string) error {
	if len(algorithms) == 0 {
		return fmt.Errorf("must not be empty")
	}
	for _, algorithm := range algorithms {
		if _, ok := supportedAlgorithms[algorithm]; !ok {
			return fmt.Errorf("unsupported signing algorithm %q", algorithm)
		}
	}
	return nil
}

func FilterSupportedAlgorithms(advertised []string) []string {
	algorithms := make([]string, 0, len(advertised))
	for _, algorithm := range advertised {
		if _, ok := supportedAlgorithms[algorithm]; ok {
			algorithms = append(algorithms, algorithm)
		}
	}
	return algorithms
}
