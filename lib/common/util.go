package common

import (
	"fmt"
	"github.com/nightlyone/lockfile"
	"github.com/subutai-io/agent/log"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"reflect"
	"runtime"
	"strconv"
	"strings"
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

func GetMajorVersion() uint16 {
	output, err := exec.Command("lxc-info", "--version").Output()
	if err != nil {
		log.Check(log.ErrorLevel, "Failed to get lxc version: ", err)
		return 0
	}
	parts := strings.Split(string(output), ".")
	if len(parts) > 0 {
		version, err := strconv.Atoi(parts[0])
		if err != nil {
			log.Check(log.ErrorLevel, "Failed to convert lxc version ", err)
			return 0
		}
		return uint16(version)
	}

	return 0
}
