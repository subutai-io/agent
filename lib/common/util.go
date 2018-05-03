package common

import (
	"strings"
	"github.com/subutai-io/agent/log"
	"runtime"
	"reflect"
)

func Splitter(s string, splits string) []string {
	m := make(map[rune]int)
	for _, r := range splits {
		m[r] = 1
	}

	splitter := func(r rune) bool {
		return m[r] == 1
	}

	return strings.FieldsFunc(s, splitter)
}

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
