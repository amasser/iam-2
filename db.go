package iam

import (
	"time"

	"github.com/boltdb/bolt"
)

type DB struct {
	db *bolt.DB
}

var globaldb *bolt.DB

func OpenDB(dbpath string) (*DB, error) {
	db, err := bolt.Open(dbpath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, err
	}

	globaldb = db

	return &DB{db}, nil
}

func InitDB() error {
	return createAuthorizeBuckets()
}

func (db *DB) Close() error {
	return db.db.Close()
}
