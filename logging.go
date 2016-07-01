package iam

import (
	"time"

	"github.com/go-kit/kit/log"
)

func loggingMiddleware(logger log.Logger) ServiceMiddleware {
	return func(next AuthorizeService) AuthorizeService {
		return logmw{logger, next}
	}
}

type logmw struct {
	logger log.Logger
	AuthorizeService
}

func (mw logmw) Authenticate(id, secret string) (output string, err error) {
	defer func(begin time.Time) {
		_ = mw.logger.Log(
			"method", "authenticate",
			"input", id,
			"output", output,
			"err", err,
			"took", time.Since(begin),
		)
	}(time.Now())

	output, err = mw.AuthorizeService.Authenticate(id, secret)
	return
}

func (mw logmw) CreateAccessKey(id, secret string) (err error) {
	defer func(begin time.Time) {
		_ = mw.logger.Log(
			"method", "create_access_key",
			"input", id,
			"err", err,
			"took", time.Since(begin),
		)
	}(time.Now())

	err = mw.AuthorizeService.CreateAccessKey(id, secret)
	return
}

func (mw logmw) Valid(token string) (err error) {
	defer func(begin time.Time) {
		_ = mw.logger.Log(
			"method", "valid",
			"err", err,
			"took", time.Since(begin),
		)
	}(time.Now())

	err = mw.AuthorizeService.Valid(token)
	return
}
