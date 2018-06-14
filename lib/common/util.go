package common

import (
	"github.com/subutai-io/agent/log"
	"runtime"
	"reflect"
)

func RunNRecover(g func()) {
	defer func() {
		if x := recover(); x != nil {
			log.Warn("Recovered from panic in "+getFunctionName(g), x)
		}
	}()
	g()
}

func getFunctionName(i interface{}) string {
	return runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
}

func Recover() {
	if r := recover(); r != nil {
		log.Warn("Recovered from ", r)
	}
}
