package iam

import (
	"errors"
	"time"
)

type AuthorizeService interface {
	Authenticate(a, b string) (string, error)
	CreateAccessKey(string, string) error
	Valid(string) error
}

type testAuthorizeService struct{}

type authorizeService struct{}

var (
	InvalidAuthorize = errors.New("invalid id or secret")
	OperationFaild   = errors.New("operator is failed")
	TokenInvalid     = errors.New("token is invalid")
	TokenExpired     = errors.New("token is expired")
	DBError          = errors.New("can't access database")
	RequestMismatch  = errors.New("request struct is mismatch")
	ExpireTime       = time.Duration(2) * time.Hour
)

const (
	DefaultKeyLength = 32
	SAFE_WORD        = "2jN6rNs0NmQKPmhpc76l2E-Y8GVRqsw7FLVANwitCCk="
)

var (
	BucketAccessKeys = []byte("AccessKey")
	BucketTokens     = []byte("Token")
	BucketExpires    = []byte("Expire")
)

func (testAuthorizeService) Authenticate(id, secret string) (string, error) {
	if id == "1234" && secret == "5678" {
		return "1234567890abcde", nil
	}

	return "", InvalidAuthorize
}

func (authorizeService) Authenticate(id, secret string) (string, error) {
	token := authenticate(id, secret)

	if len(token) > 0 {
		return token, nil
	}

	return "", InvalidAuthorize
}

func (authorizeService) CreateAccessKey(id, secret string) error {
	ok := createAccessKey(id, secret)

	if ok {
		return nil
	}

	return OperationFaild
}

func (authorizeService) Valid(token string) error {
	if len(token) == 0 {
		return errors.New("null token")
	}
	return valid(token)
}
