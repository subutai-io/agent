package fs

import (
	"path"
	"strings"
	"github.com/subutai-io/agent/log"
	"github.com/subutai-io/agent/lib/exec"
	"strconv"
	"github.com/pkg/errors"
	"github.com/subutai-io/agent/config"
)

var zfsRootDataset string
var ChildDatasets = []string{"rootfs", "home", "var", "opt"}

func init() {
	zfsRootDataset = config.Agent.Dataset
}

// Checks if dataset is readonly
// e.g. IsDatasetReadOnly("debian-stretch")
func IsDatasetReadOnly(dataset string) bool {
	out, _ := exec.ExecuteWithBash(
		"zfs get readonly -H " + path.Join(zfsRootDataset, dataset) + " | awk '{print $3}' ")
	log.Debug("Getting zfs dataset " + dataset + " readonly property " + out)
	return strings.TrimSpace(out) == "on"
}

// Sets dataset readonly
// e.g. SetDatasetReadOnly("debian-stretch")
func SetDatasetReadOnly(dataset string) {
	out, err := exec.Execute("zfs", "set", "readonly=on", path.Join(zfsRootDataset, dataset))
	log.Check(log.FatalLevel, "Setting zfs dataset "+dataset+" readonly "+out, err)
}

// Checks if dataset exists
// e.g. DatasetExists("foo")
func DatasetExists(dataset string) bool {
	out, err := exec.Execute("zfs", "list", "-H", path.Join(zfsRootDataset, dataset))
	log.Debug("Checking zfs dataset " + dataset + " existence " + out)
	return err == nil
}

// Removes dataset or snapshot.
// Parameter "recursive" allows to remove all children.
// If snapshot is to be removed, "dataset" parameter must be in form "dataset@snapshotName"
func RemoveDataset(dataset string, recursive bool) error {
	args := []string{"destroy"}
	if recursive {
		args = append(args, "-r")
	}
	args = append(args, path.Join(zfsRootDataset, dataset))
	out, err := exec.Execute("zfs", args...)
	log.Check(log.WarnLevel, "Removing zfs dataset/snapshot "+dataset+" "+out, err)
	if err != nil {
		return errors.New("Removing zfs dataset/snapshot " + dataset + " " + out)
	}
	return nil
}

// Creates dataset
// e.g. CreateDataset("debian-stretch")
func CreateDataset(dataset string) {
	out, err := exec.Execute("zfs", "create", path.Join(zfsRootDataset, dataset))
	log.Check(log.FatalLevel, "Creating zfs dataset "+dataset+" "+out, err)
}

// Receives delta file to dataset
// e.g. ReceiveStream("foo/rootfs", "/tmp/rootfs.delta")
func ReceiveStream(dataset string, delta string) {
	out, err := exec.ExecuteWithBash("zfs receive " + path.Join(zfsRootDataset, dataset) + " < " + delta)
	log.Check(log.FatalLevel, "Receving zfs stream from "+delta+" to "+dataset+" "+out, err)
}

// Saves incremental stream to delta file
// e.g. SendStream("debian-stretch/rootfs@now", "foo/rootfs@now", "/tmp/rootfs.delta")
func SendStream(snapshotFrom, snapshotTo, delta string) {
	out, err := exec.ExecuteWithBash("zfs send -i " + path.Join(zfsRootDataset, snapshotFrom) +
		" " + path.Join(zfsRootDataset, snapshotTo) + " > " + delta)
	log.Check(log.FatalLevel, "Sending zfs stream from "+snapshotFrom+" to "+snapshotTo+" > "+delta+" "+out, err)
}

// Creates snapshot
// e.g. CreateSnapshot("foo/rootfs@now")
func CreateSnapshot(snapshot string) {
	out, err := exec.Execute("zfs", "snapshot", path.Join(zfsRootDataset, snapshot))
	log.Check(log.FatalLevel, "Creating zfs snapshot "+snapshot+" "+out, err)
}

// Clones snapshot to dataset
// e.g. CloneSnapshot("debian-stretch/rootfs@now", "foo/rootfs")
func CloneSnapshot(snapshot, dataset string) {
	out, err := exec.Execute("zfs", "clone", path.Join(zfsRootDataset, snapshot),
		path.Join(zfsRootDataset, dataset))
	log.Check(log.FatalLevel, "Cloning zfs snapshot "+snapshot+" to "+dataset+" "+out, err)
}

// Sets dataset quota in GB
// e.g. SetQuota("foo", 10)
func SetQuota(dataset string, quotaInGb int) {
	out, err := exec.Execute("zfs", "set", "quota="+strconv.Itoa(quotaInGb)+"G", path.Join(zfsRootDataset, dataset))
	log.Check(log.ErrorLevel, "Setting quota "+strconv.Itoa(quotaInGb)+"G to "+dataset+" "+out, err)
}

// Returns dataset quota in bytes, 0 if no quota set
// e.g. GetQuota("foo")
func GetQuota(dataset string) (int, error) {
	out, err := exec.Execute("zfs", "get", "quota", path.Join(zfsRootDataset, dataset))
	if err != nil {
		return -1, err
	}

	lines := strings.Split(out, "\n")

	if len(lines) > 1 {
		//skip header
		fields := strings.Fields(lines[1])

		if len(fields) > 3 {

			if fields[2] == "none" {
				return 0, nil
			}

			bytes, err := ConvertToBytes(fields[2])

			log.Debug("Quota ", bytes)

			if err != nil {
				return -1, err
			}

			return bytes, nil
		} else {
			return -1, errors.New("Failed to parse quota from " + out)
		}
	} else {
		return -1, errors.New("Failed to parse quota from " + out)
	}
}

//Returns dataset disk usage in bytes
func DatasetDiskUsage(dataset string) (int, error) {

	out, err := exec.Execute("zfs", "list", path.Join(zfsRootDataset, dataset))
	if err != nil {
		return -1, err
	}

	line := strings.Split(out, "\n")

	if len(line) > 1 {
		fields := strings.Fields(line[1])

		if len(fields) > 1 {

			val, err := ConvertToBytes(fields[1])
			if err != nil {
				return -1, err
			}

			return val, nil
		}
	}

	return -1, errors.New("Failed to parse disk usage from " + out)
}

func ConvertToBytes(input string) (int, error) {
	input = strings.Replace(strings.ToUpper(strings.TrimSpace(input)), ",", ".", 1)

	multiplier := 1
	value := input

	if len(input) > 1 {

		unit := input[len(input)-1]
		value = input[:len(input)-1]
		switch unit {
		case 'K':
			multiplier = 1024
		case 'M':
			multiplier = 1024 * 1024
		case 'G':
			multiplier = 1024 * 1024 * 1024
		case 'T':
			multiplier = 1024 * 1024 * 1024 * 1024
		case 'P':
			multiplier = 1024 * 1024 * 1024 * 1024 * 1024
		case 'E':
			multiplier = 1024 * 1024 * 1024 * 1024 * 1024 * 1024
		}

	}

	num, err := strconv.ParseFloat(value, 64)
	res := float64(multiplier) * num
	return int(res), err
}
