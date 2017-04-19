package cli

import (
	"io/ioutil"
	"os"

	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/log"
	"github.com/tmc/scp"
	"golang.org/x/crypto/ssh"
)

func Migrate(name, stage, destination string) {
	if len(name) == 0 || len(stage) == 0 {
		log.Error("Specify container name and migration stage")
	}
	switch stage {
	case "1", "prepare-data":
		if len(destination) == 0 {
			log.Error("Specify destination host")
		}
		//full backup
		log.Info("Creating data backup")
		archive := config.Agent.LxcPrefix + "/backups/" + name + "_" + BackupContainer(name, true, false) + ".tar.gz"
		//transfer to destination
		log.Info("Transfering data backup to destination")
		transfer(archive, destination, config.Agent.LxcPrefix+"/backups/"+name+"_migration-stage1_Full.tar.gz")
	case "2", "import-data":
		//restore from full backup
		log.Info("Restoring data backup")
		RestoreContainer(name, "migration-stage1", name)
	case "3", "create-dump":
		if len(destination) == 0 {
			log.Error("Specify destination host")
		}
		//container freeze
		log.Warn("Freezing container")
		container.Freeze(name)
		//memory dump
		log.Info("Creating memory dump")
		Checkpoint(name, false, false)
		//diffirential backup
		log.Info("Creating diffirential data backup")
		archive := config.Agent.LxcPrefix + "/backups/" + name + "_" + BackupContainer(name, false, false) + ".tar.gz"
		//transfer to destination
		log.Info("Transfering data")
		transfer(archive, destination, config.Agent.LxcPrefix+"/backups/"+name+"_migration-stage2.tar.gz")
	case "4", "restore-dump":
		//restore diffirential backup
		log.Info("Restoring data")
		RestoreContainer(name, "migration-stage2", name)
		//restore memory dump
		log.Info("Restoring memory dump")
		Checkpoint(name, true, false)
		//Unfreeze
		log.Info("Unfreezing container")
		container.Unfreeze(name)
	}
}

func transfer(src, dst, path string) {
	key, err := ioutil.ReadFile("/root/.ssh/id_rsa")
	log.Check(log.ErrorLevel, "Reading ssh key", err)

	signer, err := ssh.ParsePrivateKey(key)
	log.Check(log.ErrorLevel, "Parsing private key", err)

	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", dst, config)
	log.Check(log.ErrorLevel, "Connecting to remote host", err)
	defer client.Close()

	session, err := client.NewSession()
	log.Check(log.ErrorLevel, "Creating session", err)

	f, err := os.Open(src)
	log.Check(log.ErrorLevel, "Opening backup archive", err)

	log.Check(log.ErrorLevel, "Copying archive", scp.CopyPath(f.Name(), path, session))
}
