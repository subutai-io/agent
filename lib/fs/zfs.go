package fs

import (
	"path"
	"strings"
	"github.com/subutai-io/agent/log"
	"github.com/subutai-io/agent/lib/exec"
	"github.com/c2h5oh/datasize"
	"strconv"
)

const ZFS_ROOT_DATASET = "subutai/fs"

// Checks if dataset is readonly
// e.g. IsDatasetReadOnly("debian-stretch")
func IsDatasetReadOnly(dataset string) bool {
	out, _ := exec.ExecuteWithBash(
		"zfs get readonly -H " + path.Join(ZFS_ROOT_DATASET, dataset) + " | awk '{print $3}' ")
	log.Debug("Getting zfs dataset " + dataset + " readonly property " + out)
	return strings.TrimSpace(out) == "on"
}

// Sets dataset readonly
// e.g. SetDatasetReadOnly("debian-stretch")
func SetDatasetReadOnly(dataset string) {
	out, err := exec.Execute("zfs", "set", "readonly=on", path.Join(ZFS_ROOT_DATASET, dataset))
	log.Check(log.FatalLevel, "Setting zfs dataset "+dataset+" readonly "+out, err)
}

// Sets dataset read-write
// e.g. SetDatasetReadWrite("debian-stretch")
func SetDatasetReadWrite(dataset string) {
	out, err := exec.Execute("zfs", "set", "readonly=off", path.Join(ZFS_ROOT_DATASET, dataset))
	log.Check(log.FatalLevel, "Setting zfs dataset "+dataset+" read-write "+out, err)
}

// Checks if dataset exists
// e.g. DatasetExists("foo")
func DatasetExists(dataset string) bool {
	out, err := exec.Execute("zfs", "list", "-H", path.Join(ZFS_ROOT_DATASET, dataset))
	log.Debug("Checking zfs dataset " + dataset + " existence " + out)
	return err == nil
}

// Removes dataset or snapshot.
// Parameter "recursive" allows to remove all children.
// If snapshot is to be removed, "dataset" parameter must be in form "dataset@snapshotName"
func RemoveDataset(dataset string, recursive bool) {
	args := []string{"destroy"}
	if recursive {
		args = append(args, "-r")
	}
	args = append(args, path.Join(ZFS_ROOT_DATASET, dataset))
	out, err := exec.Execute("zfs", args...)
	log.Check(log.WarnLevel, "Removing zfs dataset/snapshot "+dataset+" "+out, err)
}

// Creates dataset
// e.g. CreateDataset("debian-stretch")
func CreateDataset(dataset string) {
	out, err := exec.Execute("zfs", "create", path.Join(ZFS_ROOT_DATASET, dataset))
	log.Check(log.FatalLevel, "Creating zfs dataset "+dataset+" "+out, err)
}

// Receives delta file to dataset
// e.g. ReceiveStream("foo/rootfs", "/tmp/rootfs.delta")
func ReceiveStream(dataset string, delta string) {
	out, err := exec.ExecuteWithBash("zfs receive " + path.Join(ZFS_ROOT_DATASET, dataset) + " < " + delta)
	log.Check(log.FatalLevel, "Receving zfs stream from "+delta+" to "+dataset+" "+out, err)
}

// Saves incremental stream to delta file
// e.g. SendStream("debian-stretch/rootfs@now", "foo/rootfs@now", "/tmp/rootfs.delta")
func SendStream(snapshotFrom, snapshotTo, delta string) {
	out, err := exec.ExecuteWithBash("zfs send -i " + path.Join(ZFS_ROOT_DATASET, snapshotFrom) +
		" " + path.Join(ZFS_ROOT_DATASET, snapshotTo) + " > " + delta)
	log.Check(log.FatalLevel, "Sending zfs stream from "+snapshotFrom+" to "+snapshotTo+" > "+delta+" "+out, err)
}

// Sets mountpoint to dataset
// e.g. SetMountpoint("foo/rootfs", "/var/lib/subutai/lxc/foo/rootfs")
func SetMountpoint(dataset string, mountpoint string) {
	out, err := exec.Execute("zfs", "set", "mountpoint="+mountpoint, path.Join(ZFS_ROOT_DATASET, dataset))
	log.Check(log.FatalLevel, "Setting mountpoint "+mountpoint+" to zfs dataset "+dataset+" "+out, err)
}

// Creates snapshot
// e.g. CreateSnapshot("foo/rootfs@now")
func CreateSnapshot(snapshot string) {
	out, err := exec.Execute("zfs", "snapshot", path.Join(ZFS_ROOT_DATASET, snapshot))
	log.Check(log.FatalLevel, "Creating zfs snapshot "+snapshot+" "+out, err)
}

// Clones snapshot to dataset
// e.g. CloneSnapshot("debian-stretch/rootfs@now", "foo/rootfs")
func CloneSnapshot(snapshot, dataset string) {
	out, err := exec.Execute("zfs", "clone", path.Join(ZFS_ROOT_DATASET, snapshot),
		path.Join(ZFS_ROOT_DATASET, dataset))
	log.Check(log.FatalLevel, "Cloning zfs snapshot "+snapshot+" to "+dataset+" "+out, err)
}

// Sets dataset quota in GB
// e.g. SetQuota("foo", 10)
func SetQuota(dataset string, quotaInGb int) {
	out, err := exec.Execute("zfs", "set", "quota="+strconv.Itoa(quotaInGb)+"G", path.Join(ZFS_ROOT_DATASET, dataset))
	log.Check(log.ErrorLevel, "Setting quota "+strconv.Itoa(quotaInGb)+"G to "+dataset+" "+out, err)
}

// Returns dataset quota in GB
// e.g. GetQuota("foo")
func GetQuota(dataset string) int {
	out, err := exec.Execute("zfs", "get", "quota", path.Join(ZFS_ROOT_DATASET, dataset))
	log.Check(log.WarnLevel, "Reading quota of "+dataset+" "+out, err)

	fields := strings.Fields(out)

	if (len(fields) > 3) {
		var v datasize.ByteSize
		err := v.UnmarshalText([]byte(fields[2]))

		log.Check(log.WarnLevel, "Parsing quota of "+dataset+" "+out, err)

		return (int)(v.GBytes())
	} else {
		log.Warn("Failed to parse quota from " + out)
	}

	return 0
}
