// Packag template works with template deployment, configuration and initialisation
package template

import (
	"crypto/rand"
	"fmt"

	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/lib/fs"
	"github.com/subutai-io/agent/log"
	"path"
)

// Install deploys downloaded and unpacked templates to the system
func Install(templateName string) {

	pathToDecompressedTemplate := path.Join(config.Agent.LxcPrefix, "tmpdir", templateName)

	// create parent dataset
	fs.CreateDataset(templateName)

	// create partitions
	fs.ReceiveStream(templateName+"/rootfs", path.Join(pathToDecompressedTemplate, "deltas", "rootfs.delta"))
	fs.ReceiveStream(templateName+"/home", path.Join(pathToDecompressedTemplate, "deltas", "homefs.delta"))
	fs.ReceiveStream(templateName+"/var", path.Join(pathToDecompressedTemplate, "deltas", "varfs.delta"))
	fs.ReceiveStream(templateName+"/opt", path.Join(pathToDecompressedTemplate, "deltas", "optfs.delta"))

	// set partitions as read-only
	fs.SetDatasetReadOnly(templateName + "/rootfs")
	fs.SetDatasetReadOnly(templateName + "/home")
	fs.SetDatasetReadOnly(templateName + "/var")
	fs.SetDatasetReadOnly(templateName + "/opt")

	for _, file := range []string{"config", "fstab", "packages"} {
		fs.Copy(path.Join(pathToDecompressedTemplate, file), path.Join(config.Agent.LxcPrefix, templateName, file))
	}
}

// Mac function generates random mac address for LXC containers
func Mac() string {
	buf := make([]byte, 6)
	_, err := rand.Read(buf)
	log.Check(log.ErrorLevel, "Generating random mac", err)
	return fmt.Sprintf("00:16:3e:%02x:%02x:%02x", buf[3], buf[4], buf[5])
}
