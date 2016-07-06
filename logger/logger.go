package logger

import (
	"bufio"

	"github.com/go-kit/kit/log"
)

type LazyLogger struct {
	log.Logger
	w       *bufio.Writer
	logChan chan []interface{}
}

func NewLazyLogger(w *bufio.Writer) LazyLogger {
	logger := log.NewLogfmtLogger(w)
	return LazyLogger{logger, w, make(chan []interface{}, 1000)}
}

func (l LazyLogger) Log(keyvals ...interface{}) error {
	l.logChan <- keyvals
	return nil
}

func (l LazyLogger) Wait() {
	go func() {

		for {
			keyvals := <-l.logChan
			l.Logger.Log(keyvals...)
			l.w.Flush()
		}
	}()
}

func (l LazyLogger) ToLogger() log.Logger {
	return l
}
