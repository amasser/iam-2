package iam

import "errors"

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
