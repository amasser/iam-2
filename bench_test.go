package iam

import (
	"log"
	"testing"

	"github.com/valyala/gorpc"
)

func BenchmarkGorpcValid(b *testing.B) {
	var listen = "127.0.0.1:12345"

	db, err := OpenDB("iam.db")

	if err != nil {
		log.Printf("err", "open database error", err)
	}

	defer db.Close()

	d := gorpc.NewDispatcher()
	svc := authorizeService{}
	gorpc.RegisterType(&TokenRequest{})
	gorpc.RegisterType(&Response{})

	d.AddFunc("Valid", func(req *TokenRequest) *Response {
		if err := svc.Valid(req.Token); err != nil {
			return &Response{err.Error()}
		}

		return &Response{""}
	})

	s := gorpc.NewTCPServer(listen, d.NewHandlerFunc())

	if err := s.Start(); err != nil {
		log.Fatalf("Cannot start rpc server: [%s]", err)
	}
	defer s.Stop()

	c := gorpc.NewTCPClient(listen)
	c.Start()
	defer c.Stop()

	dc := d.NewFuncClient(c)

	b.SetParallelism(250)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for i := 0; pb.Next(); i++ {

			req := &TokenRequest{"8Hz1mxHu1rCqL7rq5P8B9MD7m5Qfhsw23cz7N0OW64U="}
			v, err := dc.Call("Valid", req)

			if err != nil {
				b.Fatalf("Unexpected error when calling GorpcService.Int(%d): %s", i, err)
			}
			_, ok := v.(*Response)
			if !ok {
				b.Fatalf("Unexpected response type: %T. Expected Response", v)
			}
		}
	})
}
