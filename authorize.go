package iam

import (
	"bytes"
	"fmt"
	"github.com/boltdb/bolt"
	_ "log"
	"time"
)

func authenticate(id, secret string) string {
	var token string

	err := globaldb.Update(func(tx *bolt.Tx) (err error) {
		b := tx.Bucket(BucketAccessKeys)
		v := b.Get([]byte(id))

		if string(v) == secret {
			token, err = createToken(tx, id)
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

func createToken(tx *bolt.Tx, id string) (string, error) {
	var token string
	var err error
	token, err = GenerateRandomString(DefaultKeyLength)

	b := tx.Bucket(BucketTokens)
	now := time.Now()
	expireAt := now.Add(ExpireTime)

	err = b.Put([]byte(token+":id"), []byte(id))

	bytesTime, _ := expireAt.MarshalBinary()
	err = b.Put([]byte(token+":expire_at"), bytesTime)
	err = expireKey(tx, "Token", token+":id", expireAt)
	err = expireKey(tx, "Token", token+":expire_at", expireAt)

	return token, err
}

func expireKey(tx *bolt.Tx, bucket, key string, expireAt time.Time) error {
	b := tx.Bucket(BucketExpires)
	bytesTime, _ := expireAt.MarshalBinary()
	return b.Put([]byte(bucket+":"+key), bytesTime)
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
				expireAt.UnmarshalBinary(v)
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

type ServiceMiddleware func(AuthorizeService) AuthorizeService
