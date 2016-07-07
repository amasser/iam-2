package iam

import (
	"github.com/go-kit/kit/log"
	"github.com/valyala/gorpc"
)

func GorpcServer(listen string, logger log.Logger) {
	go func() {
		d := gorpc.NewDispatcher()
		svc := authorizeService{}
		gorpc.RegisterType(&TokenRequest{})
		gorpc.RegisterType(&Response{})

		d.AddFunc("valid", func(req *TokenRequest) *Response {
			var response = &Response{svc.Valid(req.Token).Error()}
			return response
		})

		s := gorpc.NewTCPServer(listen, d.NewHandlerFunc())
		logger.Log("msg", "GORPC", "addr", listen)

		if err := s.Start(); err != nil {
			logger.Log("err", "Cannot start rpc server: [%s]", err)
		}

		defer s.Stop()
	}()
}
