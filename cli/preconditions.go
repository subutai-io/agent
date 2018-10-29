package cli

import (
	"fmt"
	"github.com/subutai-io/agent/log"
	"reflect"
)

func checkArgument(condition bool, errMsg string, vals ...interface{}) {
	checkState(condition, errMsg, vals...)
}

func checkNotNil(object interface{}, errMsg string, vals ...interface{}) {
	checkState(!IsZeroOfUnderlyingType(object), errMsg, vals...)
}

func checkState(condition bool, errMsg string, vals ...interface{}) {
	checkCondition(condition, func() {
		log.Error(fmt.Sprintf(errMsg, vals...))
	})
}

func checkCondition(condition bool, fallback func()) {
	if !condition {
		fallback()
	}
}

func IsZeroOfUnderlyingType(x interface{}) bool {
	return x == nil || reflect.DeepEqual(x, reflect.Zero(reflect.TypeOf(x)).Interface())
}
