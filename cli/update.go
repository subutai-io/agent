package cli

import (
	"os"
	"os/exec"

	"github.com/snapcore/snapd/client"
	"github.com/snapcore/snapd/store"

	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/log"
)

// Update operation can be divided into two different types: container updates and Resource Host updates.
//
// Container updates simply perform apt-get update and upgrade operations inside target containers without any extra commands.
// Since SS Management is just another container, the Subutai update command works fine with the management container too.
//
// The second type of update, a Resource Host update, checks the Ubuntu Store and compares available snap packages with those currently installed in the system and,
// if a newer version is found, installs it. Please note, system security policies requires that such commands should be performed by the superuser manually,
// otherwise an application's attempt to update itself will be blocked.
func Update(name string, check bool) {
	if !lockSubutai(name + ".update") {
		log.Error("Another update process is already running")
	}
	defer unlockSubutai()

	switch name {
	case "rh":
		local, _, _ := client.New(nil).Snap(os.Getenv("SNAP_NAME"))
		remote, _ := store.New(nil, nil).SnapInfo(store.SnapSpec{Name: os.Getenv("SNAP_NAME"), Channel: "beta"}, nil)
		if local != nil && remote != nil && remote.Revision.N > local.Revision.N {
			if check {
				log.Info("Update is available")
			} else {
				log.Check(log.FatalLevel, "Updating RH snap", exec.Command("snap", "refresh", "--devmode", os.Getenv("SNAP_NAME")).Run())
			}
			os.Exit(0)
		}
		log.Info("No update is available")
		os.Exit(1)
	default:
		if !container.IsContainer(name) {
			log.Error("no such instance \"" + name + "\"")
		}
		_, err := container.AttachExec(name, []string{"apt-get", "-qq", "update", "-y", "--force-yes", "-o", "Acquire::http::Timeout=5"})
		log.Check(log.FatalLevel, "Updating apt index", err)
		output, err := container.AttachExec(name, []string{"apt-get", "-qq", "upgrade", "-y", "--force-yes", "-o", "Acquire::http::Timeout=5", "-s"})
		log.Check(log.FatalLevel, "Checking for available update", err)
		if len(output) == 0 {
			log.Info("No update is available")
			os.Exit(1)
		} else if check {
			log.Info("Update is available")
			os.Exit(0)
		}
		_, err = container.AttachExec(name, []string{"apt-get", "-qq", "upgrade", "-y", "--allow-unauthenticated", "-o", "Acquire::http::Timeout=5", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"},
			[]string{"DEBIAN_FRONTEND=noninteractive"})
		log.Check(log.FatalLevel, "Updating container", err)
	}
}
