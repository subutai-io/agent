// Packag template works with template deployment, configuration and initialisation
package template

import (
	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/lib/fs"
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
