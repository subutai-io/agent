package net

import (
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/log"
)

// DelIface removes OVS bridges and ports by name, brings system interface down
func DelIface(iface string) {
	log.Debug("Removing interface " + iface)
	exec.Command("ovs-vsctl", "--if-exists", "del-br", iface).Run()
	exec.Command("ovs-vsctl", "--if-exists", "del-port", iface).Run()
	exec.Command("ifconfig", iface, "down").Run()
}

// RestoreDefaultConf restores default values in "hosts" and "resolv.conf" inside container
func RestoreDefaultConf(contName string) {

	filePath := config.Agent.LxcPrefix + contName + "/rootfs/etc/"

	for _, file := range []string{"hosts", "resolv.conf"} {

		doRestore(filePath, contName, file)
	}
}

func doRestore(filePath, contName, file string) {

	_, err := os.Stat(filePath + file)
	log.Check(log.PanicLevel, "Checking "+file+" file", err)

	openFile, err := os.Open(filePath + file)
	log.Check(log.PanicLevel, "Opening "+file+" file", err)
	defer openFile.Close()

	fileBck, err := os.Create(filePath + file + ".BACKUP")
	log.Check(log.PanicLevel, "Creating "+file+" backup file", err)
	defer fileBck.Close()

	_, err = io.Copy(fileBck, openFile)
	log.Check(log.FatalLevel, "Copying "+file+" backup", err)

	val := "domain\tintra.lan\nsearch\tintra.lan\nnameserver\t10.10.10.1"
	if file == "hosts" {
		val = "127.0.0.1\tlocalhost\n127.0.1.1\t" + contName
	}
	if log.Check(log.WarnLevel, "Applying new config", ioutil.WriteFile(filePath+file, []byte(val), 0644)) {
		rollbackConf(contName)
	}
}

// If RestoreDefaultConf fails, rollbackConf restores old configs
func rollbackConf(contName string) {
	filePath := config.Agent.LxcPrefix + contName + "/rootfs/etc/"
	for _, file := range []string{"hosts", "resolv.conf"} {
		log.Check(log.FatalLevel, "Removing incorrect"+file, os.Remove(filePath+file))
		log.Check(log.FatalLevel, "Restoring backup", os.Rename(filePath+file+".BACKUP", filePath+file))
	}
}

func ValidSocket(socket string) bool {
	if addr := strings.Split(socket, ":"); len(addr) == 2 {
		if _, err := net.ResolveIPAddr("ip4", addr[0]); err == nil {
			if port, err := strconv.Atoi(addr[1]); err == nil && port < 65536 {
				return true
			}
		}
	}
	return false
}
