package cli

import (
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/subutai-io/agent/config"
	lxcContainer "github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/lib/fs"
	"github.com/subutai-io/agent/lib/template"
	"github.com/subutai-io/agent/log"

	"code.cloudfoundry.org/archiver/extractor"
)

// RestoreContainer restores a Subutai container to a snapshot at a specified timestamp if such a backup archive is available.
func RestoreContainer(container, date, newContainer string, force bool) {
	if lxcContainer.ContainerOrTemplateExists(newContainer) && !force {
		log.Fatal("Container " + newContainer + " already exists")
	}

	backupDir := config.Agent.LxcPrefix + "/backups/"
	currentDT := strconv.Itoa(int(time.Now().Unix()))
	tmpUnpackDir := config.Agent.LxcPrefix + "tmpdir/unpacking_" + currentDT + "/"

	// tmpUnpackDir := backupDir + "tmpdir/unpacking_" + container + "_" + currentDT + "/"
	log.Check(log.FatalLevel, "Create UnPack tmp dir: "+tmpUnpackDir,
		os.MkdirAll(tmpUnpackDir, 0755))

	newContainerTmpDir := tmpUnpackDir + newContainer + "/"

	// making dir to newContainer
	log.Check(log.FatalLevel, "Create tmp dir for extract",
		os.MkdirAll(tmpUnpackDir+"/"+newContainer, 0755))

	flist, _ := filepath.Glob(backupDir + "*.tar.gz")
	tarball, _ := filepath.Glob(backupDir + container + "_" + date + "*.tar.gz")

	if len(tarball) == 0 {
		log.Fatal("Backup file not found: " + backupDir + container + "_" + date + "*.tar.gz")
	}

	if !strings.Contains(tarball[0], "Full") {
		// get files for unpack
		flist = append(flist[:position(flist, tarball[0])+1])
		flist = append(flist[position(flist, "Full"):])
	} else {
		flist = tarball
	}

	if !strings.Contains(flist[0], "Full") {
		log.Fatal("Cannot find Full Backup")
	}

	// UNPACKING tarballs
	for _, file := range flist {
		log.Check(log.WarnLevel, "Remove unpacked deltas dir",
			os.RemoveAll(tmpUnpackDir+container))

		log.Debug("unpacking " + file)
		unpack(file, tmpUnpackDir+container)
		deltas, _ := filepath.Glob(tmpUnpackDir + container + "/*.delta")

		// install deltas
		for _, deltaFile := range deltas {
			deltaName := strings.Replace(path.Base(deltaFile), ".delta", "", -1)
			parent := newContainerTmpDir + deltaName + "@parent"

			fs.Receive(parent, newContainerTmpDir, "unpacking_"+currentDT+"/"+container+"/"+path.Base(deltaFile),
				!strings.Contains(file, "Full"))
			fs.SubvolumeDestroy(newContainerTmpDir + deltaName + "@parent")
			log.Check(log.DebugLevel, "Rename unpacked subvolume to @parent "+newContainerTmpDir+deltaName+" -> "+newContainerTmpDir+deltaName+"@parent",
				exec.Command("mv",
					newContainerTmpDir+deltaName,
					newContainerTmpDir+deltaName+"@parent").Run())
		}
	}

	// create NewContainer subvolume
	fs.SubvolumeCreate(config.Agent.LxcPrefix + newContainer)

	// move volumes
	volumes, _ := filepath.Glob(newContainerTmpDir + "/*@parent")

	for _, volume := range volumes {
		fs.SetVolReadOnly(volume, false)
		volumeName := strings.Replace(path.Base(volume), "@parent", "", -1)

		if _, err := os.Stat(config.Agent.LxcPrefix + newContainer + "/" + volumeName); err == nil {
			log.Check(log.FatalLevel, "Copying "+volume+" content to "+config.Agent.LxcPrefix+newContainer+"/"+volumeName,
				exec.Command("rsync", "-av", volume+"/", config.Agent.LxcPrefix+newContainer+"/"+volumeName+"/").Run())
		} else {
			log.Check(log.WarnLevel, "Renaming "+volume+" to "+config.Agent.LxcPrefix+newContainer+"/"+volumeName,
				os.Rename(volume, config.Agent.LxcPrefix+newContainer+"/"+volumeName))
		}
		fs.SubvolumeDestroy(volume)
	}

	// restore meta files
	log.Check(log.FatalLevel, "Restore meta files",
		exec.Command("rsync", "-av", tmpUnpackDir+container+"/meta/", config.Agent.LxcPrefix+newContainer).Run())

	// clean
	log.Check(log.WarnLevel, "Remove unpacked deltas dir",
		os.RemoveAll(tmpUnpackDir))

	// changing newcontainer config
	lxcContainer.SetContainerConf(newContainer, [][]string{
		{"lxc.network.hwaddr", template.Mac()},
		{"lxc.network.veth.pair", strings.Replace(lxcContainer.GetConfigItem(config.Agent.LxcPrefix+newContainer+"/config", "lxc.network.hwaddr"), ":", "", -1)},
		{"lxc.network.script.up", config.Agent.AppPrefix + "bin/create_ovs_interface"},
		{"lxc.rootfs", config.Agent.LxcPrefix + newContainer + "/rootfs"},
		{"lxc.rootfs.mount", config.Agent.LxcPrefix + newContainer + "/rootfs"},
		{"lxc.mount.entry", config.Agent.LxcPrefix + newContainer + "/home home none bind,rw 0 0"},
		{"lxc.mount.entry", config.Agent.LxcPrefix + newContainer + "/opt opt none bind,rw 0 0"},
		{"lxc.mount.entry", config.Agent.LxcPrefix + newContainer + "/var var none bind,rw 0 0"},
		{"lxc.utsname", newContainer},
		{"lxc.mount", config.Agent.LxcPrefix + newContainer + "/fstab"},
	})

}

// position returns index of string from "slice" which contains "value"
func position(slice []string, value string) int {
	for p, v := range slice {
		if strings.Contains(v, value) {
			return p
		}
	}
	return -1
}

// Unpack extract passed archive to directory
func unpack(archive, dir string) {
	log.Check(log.DebugLevel, "Extracting archive", extractor.NewTgz().Extract(archive, dir))
}
