// Package fs package wraps btrfs utilities to manage filesystem snapshots, quotas, access mode, etc.
package fs

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/log"
)

// SubvolumeCreate creates BTRFS subvolume.
func SubvolumeCreate(dst string) {
	if id(dst) == "" {
		out, err := exec.Command("btrfs", "subvolume", "create", dst).CombinedOutput()
		log.Check(log.FatalLevel, "Creating subvolume "+dst+": "+string(out), err)
	}
}

// SubvolumeClone creates snapshot of the BTRFS subvolume.
func SubvolumeClone(src, dst string) {
	out, err := exec.Command("btrfs", "subvolume", "snapshot", src, dst).CombinedOutput()
	log.Check(log.FatalLevel, "Creating snapshot: "+string(out), err)
}

// SubvolumeDestroy deletes BTRFS subvolume and all subdirectories.
// It also destroys quota groups.
func SubvolumeDestroy(path string) {
	nestedvol, err := exec.Command("btrfs", "subvolume", "list", "-o", path).Output()
	log.Check(log.DebugLevel, "Getting nested subvolumes in "+path, err)

	scanner := bufio.NewScanner(bytes.NewReader(nestedvol))
	for scanner.Scan() {
		if line := strings.Fields(scanner.Text()); len(line) > 8 {
			SubvolumeDestroy(GetBtrfsRoot() + line[8])
		}
	}
	qgroupDestroy(id(path))

	out, err := exec.Command("btrfs", "subvolume", "delete", "-C", path).CombinedOutput()
	log.Check(log.DebugLevel, "Destroying subvolume "+path+": "+string(out), err)
}

// qgroupDestroy delete quota group for BTRFS subvolume.
func qgroupDestroy(index string) {
	out, err := exec.Command("btrfs", "qgroup", "destroy", index, config.Agent.LxcPrefix).CombinedOutput()
	log.Check(log.DebugLevel, "Destroying qgroup "+index+": "+string(out), err)
	log.Check(log.DebugLevel, "Destroying qgroup of parent", exec.Command("btrfs", "qgroup", "destroy", "1/"+index, config.Agent.LxcPrefix).Run())
}

// NEED REFACTORING
func id(path string) string {
	path = strings.Replace(path, config.Agent.LxcPrefix, "", -1)
	out, err := exec.Command("btrfs", "subvolume", "list", config.Agent.LxcPrefix).Output()
	log.Check(log.DebugLevel, "Getting BTRFS subvolume list", err)
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		if line := strings.Fields(scanner.Text()); len(line) > 8 && line[8] == path {
			return line[1]
		}
	}
	return ""
}

// Receive creates BTRFS subvolume using saved delta-file, it can depend on some parent.
// Parent subvolume should be installed before receiving child subvolume.
func Receive(src, dst, delta string, parent bool) {
	args := []string{"receive", "-f", config.Agent.LxcPrefix + "tmpdir/" + delta}
	if parent {
		args = append(args, "-p", src)
	}
	args = append(args, dst)
	log.Check(log.WarnLevel, "Receiving delta "+strings.Join(args, " "), exec.Command("btrfs", args...).Run())
}

// Send creates delta-file using BTRFS subvolume, it can depend on some parent.
func Send(src, dst, delta string) error {
	tmpDir, err := ioutil.TempDir(config.Agent.LxcPrefix+"tmpdir/", "export")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	if path := strings.Split(dst, "/"); len(path) > 0 {
		tmpVolume := tmpDir + "/" + path[len(path)-1]

		SubvolumeClone(dst, tmpVolume)
		defer SubvolumeDestroy(tmpVolume)
		SetVolReadOnly(tmpVolume, true)

		args := []string{"btrfs", "send"}
		if src != dst {
			args = append(args, "-p", src)
		}
		args = append(args, tmpVolume, ">", delta)

		return exec.Command("/bin/bash", "-c", strings.Join(args, " ")).Run()
	}
	return nil
}

// SetVolReadOnly sets readonly flag for BTRFS subvolume.
func SetVolReadOnly(subvol string, flag bool) {
	out, err := exec.Command("btrfs", "property", "set", "-ts", subvol, "ro", strconv.FormatBool(flag)).CombinedOutput()
	log.Check(log.FatalLevel, "Setting readonly: "+strconv.FormatBool(flag)+": "+string(out), err)
}

// GetBtrfsRoot returns BTRFS root
func GetBtrfsRoot() string {
	data, err := exec.Command("findmnt", "-nT", config.Agent.LxcPrefix).Output()
	log.Check(log.FatalLevel, "Searching btrfs mount point", err)
	return strings.Fields(string(data))[0] + "/"
}
