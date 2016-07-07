package iam

import (
	"encoding/json"
	"net/http"
	"os"
	"os/signal"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"

	"golang.org/x/net/context"
)

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

func HttpServer(listen string, logger log.Logger) {
	go func() {
		http.Handle("/authenticate", AuthenticateHandler(logger))
		http.Handle("/access_keys", CreateAccessKeyHandler(logger))
		http.Handle("/valid", ValidHandler(logger))

		logger.Log("msg", "HTTP", "addr", listen)
		logger.Log("err", http.ListenAndServe(listen, nil))
	}()
}

func Wait() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for _ = range c {
			// sig is a ^C, handle it
		}
	}()

	<-c
}
