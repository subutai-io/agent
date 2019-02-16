package cli

import (
	"github.com/subutai-io/agent/lib/container"
	"strings"
	"path"
	"github.com/subutai-io/agent/config"
	"os"
	"github.com/subutai-io/agent/lib/fs"
	"github.com/subutai-io/agent/log"
	"time"
)

//todo move functionality to lib and here delegate there

func BackupContainer(containerName, backupName string) {

	backupName = strings.TrimSpace(backupName)
	containerName = strings.TrimSpace(containerName)

	checkArgument(backupName != "", "Invalid backup name")

	checkState(container.IsContainer(containerName), "Container %s not found", containerName)

	if container.State(containerName) == container.Running {
		LxcStop(containerName)
		defer LxcStart(containerName)
	}

	//cleanup files
	src := path.Join(config.Agent.LxcPrefix, containerName)
	cleanupFS(path.Join(src, "/var/log"), 0775) // should we clean log??
	cleanupFS(path.Join(src, "/var/cache"), 0775)
	cleanupFS(path.Join(src, "/var/tmp"), 0775)

	//create deltas
	dst := path.Join(config.Agent.CacheDir, backupName)
	os.MkdirAll(dst, 0755)
	os.MkdirAll(dst+"/deltas", 0755)

	parent := container.GetProperty(containerName, "subutai.parent")
	parentOwner := container.GetProperty(containerName, "subutai.parent.owner")
	parentVersion := container.GetProperty(containerName, "subutai.parent.version")
	parentRef := strings.Join([]string{parent, parentOwner, parentVersion}, ":")

	for _, vol := range fs.ChildDatasets {
		snapshot := containerName + "/" + vol + "@now"

		//remove old snapshot if any
		if fs.DatasetExists(snapshot) {
			fs.RemoveDataset(snapshot, false)
		}
		// snapshot each partition
		err := fs.CreateSnapshot(snapshot)
		log.Check(log.ErrorLevel, "Creating snapshot "+snapshot, err)

		// send incremental delta between parent and child to delta file
		err = fs.SendStream(parentRef+"/"+vol+"@now", containerName+"/"+vol+"@now", dst+"/deltas/"+vol+".delta")
		log.Check(log.ErrorLevel, "Sending stream for partition "+vol, err)
	}

	time.Sleep(1000)

	for _, vol := range fs.ChildDatasets {
		snapshot := containerName + "/" + vol + "@now"

		//remove snapshot to save space
		err := fs.RemoveDataset(snapshot, false)
		log.Check(log.ErrorLevel, "Removing snapshot "+snapshot, err)
	}

	log.Check(log.ErrorLevel, "Copying config file", fs.Copy(src+"/config", dst+"/config"))

	//archive template contents
	backupArchive := dst + ".tar.gz"
	fs.Compress(dst, backupArchive)
	log.Check(log.WarnLevel, "Removing temporary directory", os.RemoveAll(dst))
	log.Info(containerName + " got backed up to " + backupArchive)

}
