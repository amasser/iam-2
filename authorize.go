package iam

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/boltdb/bolt"
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
	return valid(token)
}

func authenticate(id, secret string) string {
	var token string

	err := globaldb.View(func(tx *bolt.Tx) (err error) {
		b := tx.Bucket(BucketAccessKeys)
		v := b.Get([]byte(id))

		if string(v) == secret {
			token, err = createToken(id)
		} else {
			return InvalidAuthorize
		}

		return err
	})

	if err != nil {
		return ""
	}

	return token
}

func createAccessKey(id, secret string) bool {
	err := globaldb.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketAccessKeys)
		err := b.Put([]byte(id), []byte(secret))

		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return false
	}

	return true
}

func createToken(id string) (string, error) {
	var token string
	var err error
	token, err = GenerateRandomString(DefaultKeyLength)

	err = globaldb.Batch(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketTokens)
		now := time.Now()
		expireAt := now.Add(ExpireTime)

		err := b.Put([]byte(token+":id"), []byte(id))
		err = b.Put([]byte(token+":expire_at"), []byte(expireAt.String()))
		err = expireKey(tx, "Token", token+":id", expireAt)
		err = expireKey(tx, "Token", token+":expire_at", expireAt)

		return err
	})

	return token, err
}

func expireKey(tx *bolt.Tx, bucket, key string, expireAt time.Time) error {
	b := tx.Bucket(BucketExpires)
	return b.Put([]byte(bucket+":"+key), []byte(expireAt.String()))
}

func valid(token string) error {
	var id string
	var expireAt time.Time
	err := globaldb.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(BucketTokens).Cursor()

		prefix := []byte(token)

		for k, v := c.Seek(prefix); bytes.HasPrefix(k, prefix); k, v = c.Next() {
			if string(k) == token+":id" {
				id = string(v)
			}

			if string(k) == token+":expire_at" {
				expireAt, _ = time.Parse("2013-02-03 19:54:00 -0800 PST", string(v))
			}

			if len(id) > 0 && !expireAt.IsZero() {
				break
			}
		}

		if len(id) == 0 || expireAt.IsZero() {
			return TokenInvalid
		}

		if time.Now().After(expireAt) {
			return TokenExpired
		}

		return nil
	})

	return err
}

func createAuthorizeBuckets() error {
	err := globaldb.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucket(BucketAccessKeys)
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}

		token, err := GenerateRandomString(DefaultKeyLength)
		if err != nil {
			return err
		}

		b.Put([]byte("root"), []byte(token))

		_, err = tx.CreateBucket(BucketTokens)
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}

		_, err = tx.CreateBucket(BucketExpires)
		if err != nil {
			return fmt.Errorf("create bucket: %s", err)
		}
		return nil
	})

	return err
}

func RootSecret(word string) string {
	var secret string

	if word != SAFE_WORD {
		return ""
	}

	err := globaldb.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketAccessKeys)
		v := b.Get([]byte("root"))

		secret = string(v)
		return nil
	})

	if err != nil {
		return ""
	}

	return secret
}
