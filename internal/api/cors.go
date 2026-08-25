package api

import (
	"net/http"

	"github.com/rs/cors"
)

var defaultCORSOptions = cors.Options{
	AllowCredentials: true,
	AllowedHeaders: []string{
		"Origin",
		"Accept",
		"Accept-Language",
		"Authorization",
		"Content-Type",
		"X-Requested-With",
	},
	AllowedMethods: []string{
		http.MethodGet,
		http.MethodHead,
		http.MethodPost,
	},
	ExposedHeaders: []string{
		"Location",
		"Content-Length",
	},
	AllowOriginFunc: func(_ string) bool {
		return true
	},
}
