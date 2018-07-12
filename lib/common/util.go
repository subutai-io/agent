package common

import (
	"github.com/subutai-io/agent/log"
	"runtime"
	"reflect"
	"github.com/nightlyone/lockfile"
	"io/ioutil"
	"fmt"
	"strings"
	"os"
	"path"
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

func LockFile(name string, command string) (lockfile.Lockfile, error) {
	file := strings.Join([]string{"subutai", command, name}, ".")
	lockFile := path.Join("/var/run/lock/", file)

	lock, err := lockfile.New(lockFile)
	if log.Check(log.DebugLevel, "Init lock "+file, err) {
		return lock, err
	}

	err = lock.TryLock()
	if log.Check(log.DebugLevel, "Locking file "+file, err) {
		if p, err2 := lock.GetOwner(); err2 == nil {
			cmd, err2 := ioutil.ReadFile(fmt.Sprintf("/proc/%v/cmdline", p.Pid))
			if err2 != nil || !(strings.Contains(string(cmd), "subutai") && strings.Contains(string(cmd), command)) {
				log.Check(log.DebugLevel, "Removing broken lock file "+lockFile, os.Remove(lockFile))
			}
		}
		return lock, err
	}

	return lock, nil
}
