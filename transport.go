package iam

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-kit/kit/endpoint"
	httptransport "github.com/go-kit/kit/transport/http"

	"golang.org/x/net/context"
)

var (
	InvalidToken = errors.New("authorize faild. invalid token")
)

type authenticateRequest struct {
	ID     string `json:"id"`
	Secret string `json:"secret"`
}

type authenticateResponse struct {
	Token string `json:"token"`
	Err   string `json:"err,omitempty"` // errors don't JSON-marshal, so we use a string
}

type TokenRequest struct {
	Token string `json:"token"`
}

type createAccessKeyRequest struct {
	TokenRequest
	ID     string `json:"id"`
	Secret string `json:"secret"`
}

type successResponse struct {
	success bool   `json:"success"`
	Err     string `json:"err,omitempty"` // errors don't JSON-marshal, so we use a string
}

func makeAuthenticateEndpoint(svc AuthorizeService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(authenticateRequest)
		token, err := svc.Authenticate(req.ID, req.Secret)
		if err != nil {
			return authenticateResponse{token, err.Error()}, nil
		}
		return authenticateResponse{token, ""}, nil
	}
}

func makeCreateAccessKeyEndpoint(svc AuthorizeService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(createAccessKeyRequest)
		if err := svc.Valid(req.Token); err != nil {
			return successResponse{false, err.Error()}, nil
		}

		err := svc.CreateAccessKey(req.ID, req.Secret)

		if err != nil {
			return successResponse{false, err.Error()}, nil
		}

		return successResponse{true, ""}, nil
	}
}

func decodeAuthenticateRequest(_ context.Context, r *http.Request) (interface{}, error) {
	var request authenticateRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		return nil, err
	}
	return request, nil
}

func decodeAccessKeyRequest(_ context.Context, r *http.Request) (interface{}, error) {
	var request createAccessKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		return nil, err
	}
	return request, nil
}

func AuthenticateHandler() *httptransport.Server {
	var svc AuthorizeService
	ctx := context.Background()
	svc = authorizeService{}
	// logger := log.NewLogfmtLogger(os.Stderr)
	// svc = loggingMiddleware{logger, svc}

	return httptransport.NewServer(
		ctx,
		makeAuthenticateEndpoint(svc),
		decodeAuthenticateRequest,
		encodeResponse,
	)
}

func CreateAccessKeyHandler() *httptransport.Server {
	var svc AuthorizeService
	ctx := context.Background()
	svc = authorizeService{}
	// logger := log.NewLogfmtLogger(os.Stderr)
	// svc = loggingMiddleware{logger, svc}

	return httptransport.NewServer(
		ctx,
		makeCreateAccessKeyEndpoint(svc),
		decodeAccessKeyRequest,
		encodeResponse,
	)
}
