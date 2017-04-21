package cli

import (
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/lib/net"
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
		checkDestination(&destination)
		//full backup
		log.Info("Creating data backup")
		archive := BackupContainer(name, true, false)
		//transfer to destination
		log.Info("Sending data backup to destination")
		transfer(archive, destination, config.Agent.LxcPrefix+"/backups/"+name+"_migration-stage1_Full.tar.gz")
	case "2", "import-data":
		//restore from full backup
		log.Info("Restoring data backup")
		RestoreContainer(name, "migration-stage1", name, false)
	case "3", "create-dump":
		checkDestination(&destination)
		//memory dump
		log.Info("Creating memory dump")
		res := Checkpoint(name, false, false)
		for counter := 0; !res && counter < 3; res = Checkpoint(name, false, false) {
			log.Warn("Retrying memory dump")
			time.Sleep(time.Second * 1)
			counter++
		}
		//container freeze
		log.Warn("Freezing container")
		container.Freeze(name)
		//diffirential backup
		log.Info("Creating diffirential data backup")
		archive := BackupContainer(name, false, false)
		//cleaning container directory
		log.Check(log.WarnLevel, "Removing memory images",
			os.RemoveAll(config.Agent.LxcPrefix+name+"/checkpoint"))
		log.Check(log.WarnLevel, "Removing start trigger",
			os.Remove(config.Agent.LxcPrefix+name+"/.start"))
		//transfer to destination
		log.Info("Sending data")
		transfer(archive, destination, config.Agent.LxcPrefix+"/backups/"+name+"_migration-stage2.tar.gz")
	case "4", "restore-dump":
		//restore diffirential backup
		log.Info("Restoring data")
		RestoreContainer(name, "migration-stage2", name, true)
		//restore memory dump
		log.Info("Restoring memory dump")
		Checkpoint(name, true, false)
		//Unfreeze
		log.Info("Unfreezing container")
		container.Unfreeze(name)
		_, err := os.Create(config.Agent.LxcPrefix + name + "/.start")
		log.Check(log.WarnLevel, "Creating start trigger", err)
	case "5", "unfreeze":
		//Unfreeze
		log.Info("Unfreezing container")
		container.Unfreeze(name)
		_, err := os.Create(config.Agent.LxcPrefix + name + "/.start")
		log.Check(log.WarnLevel, "Restoring start trigger", err)
	}
}

func transfer(src, dst, path string) {
	client, err := sshClient(dst)
	log.Check(log.ErrorLevel, "Creating connection", err)
	defer client.Close()

	session, err := client.NewSession()
	log.Check(log.ErrorLevel, "Creating session", err)

	f, err := os.Open(src)
	log.Check(log.ErrorLevel, "Opening backup archive", err)

	log.Check(log.ErrorLevel, "Copying archive", scp.CopyPath(f.Name(), path, session))
}

func checkDestination(destination *string) {
	if len(strings.Split(*destination, ":")) == 1 {
		*destination += ":22"
	}
	if !net.ValidSocket(*destination) {
		log.Error("Please specify valid destination socket")
	}

	client, err := sshClient(*destination)
	log.Check(log.ErrorLevel, "Creating connection", err)
	client.Close()
}

func sshClient(destination string) (*ssh.Client, error) {
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
	client, err := ssh.Dial("tcp", destination, config)
	return client, err
}
