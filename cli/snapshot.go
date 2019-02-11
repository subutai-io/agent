package cli

import (
	"strings"
	"github.com/subutai-io/agent/lib/fs"
	container2 "github.com/subutai-io/agent/lib/container"
	"fmt"
	"github.com/subutai-io/agent/log"
)

//todo remove code duplicates

func CreateSnapshot(container, partition, label string) {

	container = strings.ToLower(strings.TrimSpace(container))
	partition = strings.ToLower(strings.TrimSpace(partition))
	label = strings.ToLower(strings.TrimSpace(label))

	checkArgument(container != "", "Invalid container name")

	checkArgument(partition != "", "Invalid container partition")
	partitionFound := false
	for _, vol := range fs.ChildDatasets {
		if vol == partition {
			partitionFound = true
			break
		}
	}
	checkArgument(partitionFound, "Invalid partition %s", partition)

	checkArgument(label != "", "Invalid snapshot label")

	// check that container exists
	checkState(container2.IsContainer(container), "Container %s not found", container)
	// check that snapshot with such label does not exist
	snapshot := fmt.Sprintf("%s/%s@%s", container, partition, label)
	checkState(!fs.DatasetExists(snapshot), "Snapshot %s already exists", snapshot)

	// create snapshot
	err := fs.CreateSnapshot(snapshot)
	checkCondition(err == nil, func() {
		log.Error("Failed to create snapshot ", err.Error())
	})
}

func RemoveSnapshot(container, partition, label string) {
	container = strings.ToLower(strings.TrimSpace(container))
	partition = strings.ToLower(strings.TrimSpace(partition))
	label = strings.ToLower(strings.TrimSpace(label))

	checkArgument(container != "", "Invalid container name")

	checkArgument(partition != "", "Invalid container partition")
	partitionFound := false
	for _, vol := range fs.ChildDatasets {
		if vol == partition {
			partitionFound = true
			break
		}
	}
	checkArgument(partitionFound, "Invalid partition %s", partition)

	checkArgument(label != "", "Invalid snapshot label")

	// check that container exists
	checkState(container2.IsContainer(container), "Container %s not found", container)
	// check that snapshot with such label exists
	snapshot := fmt.Sprintf("%s/%s@%s", container, partition, label)
	checkState(fs.DatasetExists(snapshot), "Snapshot %s does not exist", snapshot)

	err := fs.RemoveDataset(snapshot, false)
	checkCondition(err == nil, func() {
		log.Error("Failed to remove snapshot ", err.Error())
	})
}

func ListSnapshots(container, partition string) string {
	container = strings.ToLower(strings.TrimSpace(container))
	partition = strings.ToLower(strings.TrimSpace(partition))

	checkArgument(container != "", "Invalid container name")

	if partition != "" {
		partitionFound := false
		for _, vol := range fs.ChildDatasets {
			if vol == partition {
				partitionFound = true
				break
			}
		}
		checkArgument(partitionFound, "Invalid partition %s", partition)
	}

	// check that container exists
	checkState(container2.IsContainer(container), "Container %s not found", container)

	var out string
	var err error
	if partition != "" {
		out, err = fs.ListSnapshots(fmt.Sprintf("%s/%s", container, partition))
	} else {
		out, err = fs.ListSnapshots(container)
	}
	checkCondition(err == nil, func() {
		log.Error("Failed to list snapshots ", err.Error())
	})

	return out
}

func RollbackToSnapshot(container, partition, label string) {
	container = strings.ToLower(strings.TrimSpace(container))
	partition = strings.ToLower(strings.TrimSpace(partition))
	label = strings.ToLower(strings.TrimSpace(label))

	checkArgument(container != "", "Invalid container name")

	checkArgument(partition != "", "Invalid container partition")
	partitionFound := false
	for _, vol := range fs.ChildDatasets {
		if vol == partition {
			partitionFound = true
			break
		}
	}
	checkArgument(partitionFound, "Invalid partition %s", partition)

	checkArgument(label != "", "Invalid snapshot label")

	// check that container exists
	checkState(container2.IsContainer(container), "Container %s not found", container)
	// check that snapshot with such label exists
	snapshot := fmt.Sprintf("%s/%s@%s", container, partition, label)
	checkState(fs.DatasetExists(snapshot), "Snapshot %s does not exist", snapshot)

	err := fs.RollbackToSnapshot(snapshot)
	checkCondition(err == nil, func() {
		log.Error("Failed to rollback to snapshot", err.Error())
	})

}
