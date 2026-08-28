package http

import (
	http2 "net/http"

	"github.com/muhlemmer/gu"
	http3 "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/op"
)

func Respond(w http2.ResponseWriter, r *http2.Request, data any, err error) {
	if err != nil {
		op.WriteError(w, r, err, nil)
		return
	}
	RespondSuccess(data)(w, r)
}

func RespondSuccess(data any) http2.HandlerFunc {
	return func(w http2.ResponseWriter, r *http2.Request) {
		resp, ok := data.(*op.Response)
		if !ok {
			resp = op.NewResponse(data)
		}
		gu.MapMerge(resp.Header, w.Header())
		http3.MarshalJSON(w, resp.Data)
	}
}
