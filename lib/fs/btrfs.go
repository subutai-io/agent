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

// IsSubvolumeReadonly checks if BTRFS subvolume have "readonly" property.
// It's used in Subutai to check if LXC container template or not.
func IsSubvolumeReadonly(path string) bool {
	out, err := exec.Command("btrfs", "property", "get", "-ts", path).Output()
	log.Check(log.DebugLevel, "Getting BTRFS subvolume readonly property", err)
	return strings.Contains(string(out), "true")
}
func IsSubvolumeReadWrite(path string) bool {
	out, err := exec.Command("btrfs", "property", "get", "-ts", path).Output()
	log.Check(log.DebugLevel, "Getting BTRFS subvolume readonly property", err)
	return strings.Contains(string(out), "false")
}

func DiskUsage(container string) string {

	out, err := exec.Command("btrfs", "filesystem", "du", "-s", "--raw", config.Agent.LxcPrefix+container).CombinedOutput()

	log.Check(log.ErrorLevel, "Checking disk usage of container "+container+": "+string(out), err)

	output := strings.Split(string(out), "\n")

	for idx, line := range output {

		//skip header
		if idx == 1 {

			return strings.Fields(line)[0]
		}

	}

	log.Error("Failed to parse output: " + string(out))

	//should not reach here
	return ""
}

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
	args := []string{"receive", dst, "-f", config.Agent.LxcPrefix + "tmpdir/" + delta}
	if parent {
		args = append(args, "-p", src)
	}
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

		if src != dst {
			return exec.Command("btrfs", "send", "-p", src, tmpVolume, "-f", delta).Run()
		}
		return exec.Command("btrfs", "send", tmpVolume, "-f", delta).Run()
	}
	return nil
}

// ReadOnly sets readonly flag for Subutai container.
// Subvolumes with active readonly flag is Subutai templates.
func ReadOnly(container string, flag bool) {
	for _, path := range []string{container + "/rootfs/", container + "/opt", container + "/var", container + "/home"} {
		SetVolReadOnly(config.Agent.LxcPrefix+path, flag)
	}
}

// SetVolReadOnly sets readonly flag for BTRFS subvolume.
func SetVolReadOnly(subvol string, flag bool) {
	out, err := exec.Command("btrfs", "property", "set", "-ts", subvol, "ro", strconv.FormatBool(flag)).CombinedOutput()
	log.Check(log.FatalLevel, "Setting readonly: "+strconv.FormatBool(flag)+": "+string(out), err)
}

// Stat returns quota and usage for BTRFS subvolume.
func Stat(path, index string, raw bool) (value string) {
	var row = map[string]int{"quota": 4, "usage": 2}

	args := []string{"qgroup", "show", "-re", config.Agent.LxcPrefix}
	if raw {
		args = []string{"qgroup", "show", "-re", "--raw", config.Agent.LxcPrefix}
	}
	out, err := exec.Command("btrfs", args...).Output()
	log.Check(log.FatalLevel, "Getting btrfs stats", err)
	ind := id(path)
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		if line := strings.Fields(scanner.Text()); len(line) > 3 && strings.HasSuffix(line[0], "/"+ind) {
			value = line[row[index]]
		}
	}
	return value
}

// DiskQuota returns total disk quota for Subutai container.
// If size argument is set, it sets new quota value.
func DiskQuota(path string, size ...string) string {
	parent := id(path)
	exec.Command("btrfs", "qgroup", "create", "1/"+parent, config.Agent.LxcPrefix+path).Run()
	exec.Command("btrfs", "qgroup", "assign", "0/"+id(path+"/opt"), "1/"+parent, config.Agent.LxcPrefix+path).Run()
	exec.Command("btrfs", "qgroup", "assign", "0/"+id(path+"/var"), "1/"+parent, config.Agent.LxcPrefix+path).Run()
	exec.Command("btrfs", "qgroup", "assign", "0/"+id(path+"/home"), "1/"+parent, config.Agent.LxcPrefix+path).Run()
	exec.Command("btrfs", "qgroup", "assign", "0/"+id(path+"/rootfs"), "1/"+parent, config.Agent.LxcPrefix+path).Run()

	if len(size) > 0 && len(size[0]) > 0 {
		out, err := exec.Command("btrfs", "qgroup", "limit", "-e", size[0]+"G", "1/"+parent, config.Agent.LxcPrefix+path).CombinedOutput()
		log.Check(log.ErrorLevel, "Limiting BTRFS group 1/"+parent+" "+string(out), err)
		exec.Command("btrfs", "quota", "rescan", "-w", config.Agent.LxcPrefix).Run()
	}
	return Stat(path, "quota", false)
}

// Quota returns subvolume quota.
// If size argument is set, it sets new quota value.
func Quota(path string, size ...string) string {
	if len(size) > 0 && len(size[0]) > 0 {
		out, err := exec.Command("btrfs", "qgroup", "limit", "-e", size[0]+"G", config.Agent.LxcPrefix+path).CombinedOutput()
		log.Check(log.ErrorLevel, "Limiting BTRFS subvolume "+config.Agent.LxcPrefix+path+" "+string(out), err)
		exec.Command("btrfs", "quota", "rescan", "-w", config.Agent.LxcPrefix).Run()
	}
	return Stat(path, "quota", false)
}

// GetBtrfsRoot returns BTRFS root
func GetBtrfsRoot() string {
	data, err := exec.Command("findmnt", "-nT", config.Agent.LxcPrefix).Output()
	log.Check(log.FatalLevel, "Searching btrfs mount point", err)
	return strings.Fields(string(data))[0] + "/"
}
