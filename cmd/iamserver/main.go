package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/go-kit/kit/log"
	"github.com/wanliu/iam"
	wl "github.com/wanliu/iam/logger"
)

// +build linux darwin
// +build x64

func main() {
	var (
		safeword = flag.String("safe", "", "access root secret must have a safe secret key")
		listen   = flag.String("listen", ":8080", "HTTP listen address")
		dbpath   = flag.String("dbpath", "iam.db", "IAM store database")
		verbose  = flag.String("verbose", "log", "log info level")
		command  = ""
		// proxy  = flag.String("proxy", "", "Optional comma-separated list of URLs to proxy uppercase requests")
	)

	flag.Parse()

	var logger log.Logger
	var lazyLogger wl.LazyLogger

	if *verbose == "nil" {

		logger = log.NewLogfmtLogger(ioutil.Discard)
	} else {
		f, _ := os.Create("/tmp/iamserver.log")
		w := bufio.NewWriter(f)
		lazyLogger = wl.NewLazyLogger(w)
	}
	lazyLogger.Wait()

	logger = log.NewContext(lazyLogger).With("listen", *listen).With("caller", log.DefaultCaller)

	if len(flag.Args()) > 0 {
		command = flag.Arg(0)
		flag.CommandLine.Parse(flag.Args()[1:])
	}

	db, err := iam.OpenDB(*dbpath)

	if err != nil {
		logger.Log("err", "open database error", err)
	}

	defer db.Close()

	switch command {
	case "initdb":
		initdb(logger)
		return
	case "genkey":
		fmt.Printf("generate unique key: %s\n", generateKey())
		return
	case "rootkey":

		key := rootSecret(*safeword)
		if key == "" {
			logger.Log("err", "safe word is wrong!")
		}

		fmt.Printf("root secret key is: %s\n", key)
		return
	case "":
		break
	default:
		flag.PrintDefaults()
	}

	iam.HttpServer(*listen, logger)
	iam.GorpcServer("127.0.0.1:12345", logger)
	iam.Wait()
}

func initdb(logger log.Logger) {
	err := iam.InitDB()
	if err != nil {
		logger.Log("err", "init db...", err)
	}
	logger.Log("msg", "init db success.")
	os.Exit(0)
}

func generateKey() string {
	key, _ := iam.GenerateRandomString(32)
	return key
}

func rootSecret(safeKey string) string {
	return iam.RootSecret(safeKey)
}
