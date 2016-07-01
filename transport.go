package iam

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
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

type Response struct {
	Err string `json:"err,omitempty"` // errors don't JSON-marshal, so we use a string
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

func makeValidEndpoint(svc AuthorizeService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(TokenRequest)
		err := svc.Valid(req.Token)
		if err != nil {
			return Response{err.Error()}, nil
		}
		return Response{""}, nil
	}
}

func decodeValidRequest(_ context.Context, r *http.Request) (interface{}, error) {
	var request TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		return nil, err
	}
	return request, nil
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

func AuthenticateHandler(logger log.Logger) *httptransport.Server {
	var svc AuthorizeService
	ctx := context.Background()
	svc = authorizeService{}
	svc = loggingMiddleware(logger)(svc)

	return httptransport.NewServer(
		ctx,
		makeAuthenticateEndpoint(svc),
		decodeAuthenticateRequest,
		encodeResponse,
	)
}

func CreateAccessKeyHandler(logger log.Logger) *httptransport.Server {
	var svc AuthorizeService
	ctx := context.Background()
	svc = authorizeService{}
	svc = loggingMiddleware(logger)(svc)

	return httptransport.NewServer(
		ctx,
		makeCreateAccessKeyEndpoint(svc),
		decodeAccessKeyRequest,
		encodeResponse,
	)
}

func ValidHandler(logger log.Logger) *httptransport.Server {
	var svc AuthorizeService
	ctx := context.Background()
	svc = authorizeService{}
	svc = loggingMiddleware(logger)(svc)

	return httptransport.NewServer(
		ctx,
		makeValidEndpoint(svc),
		decodeValidRequest,
		encodeResponse,
	)
}
