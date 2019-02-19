package cli

import (
	"strings"
	"github.com/subutai-io/agent/lib/fs"
	container2 "github.com/subutai-io/agent/lib/container"
	"fmt"
	"github.com/subutai-io/agent/log"
	"github.com/subutai-io/agent/config"
	"path"
)

func CreateSnapshot(container, partition, label string, stopContainer bool) {

	container = strings.TrimSpace(container)
	partition = strings.ToLower(strings.TrimSpace(partition))
	label = strings.ToLower(strings.TrimSpace(label))

	checkArgument(container != "", "Invalid container name")

	if partition != "all" {
		checkPartitionName(partition)
	}

	checkArgument(label != "", "Invalid snapshot label")

	// check that container exists
	checkState(container2.IsContainer(container), "Container %s not found", container)
	// check that snapshot with such label does not exist
	snapshot := getSnapshotName(container, partition, label)
	checkState(!fs.DatasetExists(snapshot), "Snapshot %s already exists", snapshot)

	if stopContainer {
		if container2.State(container) == container2.Running {
			LxcStop(container)
			defer LxcStart(container)
		}
	}

	// create snapshot
	err := fs.CreateSnapshot(snapshot, partition == "all")
	checkCondition(err == nil, func() {
		log.Error("Failed to create snapshot ", err.Error())
	})
}

func RemoveSnapshot(container, partition, label string) {
	container = strings.TrimSpace(container)
	partition = strings.ToLower(strings.TrimSpace(partition))
	label = strings.ToLower(strings.TrimSpace(label))

	checkArgument(container != "", "Invalid container name")

	checkPartitionName(partition)

	checkArgument(label != "", "Invalid snapshot label")

	// check that container exists
	checkState(container2.IsContainer(container), "Container %s not found", container)
	// check that snapshot with such label exists
	snapshot := getSnapshotName(container, partition, label)
	checkState(fs.DatasetExists(snapshot), "Snapshot %s does not exist", snapshot)

	err := fs.RemoveDataset(snapshot, false)
	checkCondition(err == nil, func() {
		log.Error("Failed to remove snapshot ", err.Error())
	})
}

func ListSnapshots(container, partition string) string {
	container = strings.TrimSpace(container)
	partition = strings.ToLower(strings.TrimSpace(partition))

	if partition != "" {
		//check that container is specified if partition is present
		checkArgument(container != "", "Please, specify container name")
	}

	if container != "" {
		// check that container exists
		checkState(container2.IsContainer(container), "Container %s not found", container)
	}

	if partition != "" {
		partitionFound := false
		for _, vol := range fs.ChildDatasets {
			if vol == partition {
				partitionFound = true
				break
			}
		}
		if partition == "parent" {
			partitionFound = true
		}
		checkArgument(partitionFound, "Invalid partition %s", partition)
	}

	var out string
	var err error
	if container == "" {
		//list snapshots of all containers
		out, err = fs.ListSnapshots("")
		//remove lines belonging to templates
		if err == nil {
			lines := strings.Split(out, "\n")
			templates := container2.Templates()
			out = ""
			for _, line := range lines {
				found := false
				for _, template := range templates {
					if strings.Contains(line, path.Join(config.Agent.Dataset, template)+"/") {
						found = true
						break
					}
				}
				if !found {
					out += line + "\n"
				}
			}
		}

	} else {
		if partition != "" {
			out, err = fs.ListSnapshots(getSnapshotName(container, partition, ""))
		} else {
			out, err = fs.ListSnapshots(container)
		}
	}

	checkCondition(err == nil, func() {
		log.Error("Failed to list snapshots ", err.Error())
	})

	out = strings.TrimRight(out, "\n")

	return out
}

func RollbackToSnapshot(container, partition, label string, stopContainer bool) {
	container = strings.TrimSpace(container)
	partition = strings.ToLower(strings.TrimSpace(partition))
	label = strings.ToLower(strings.TrimSpace(label))

	checkArgument(container != "", "Invalid container name")

	checkPartitionName(partition)

	checkArgument(label != "", "Invalid snapshot label")

	// check that container exists
	checkState(container2.IsContainer(container), "Container %s not found", container)
	// check that snapshot with such label exists
	snapshot := getSnapshotName(container, partition, label)
	checkState(fs.DatasetExists(snapshot), "Snapshot %s does not exist", snapshot)

	if stopContainer {
		if container2.State(container) == container2.Running {
			LxcStop(container)
			defer LxcStart(container)
		}
	}

	err := fs.RollbackToSnapshot(snapshot)
	checkCondition(err == nil, func() {
		log.Error("Failed to rollback to snapshot", err.Error())
	})
}

func getSnapshotName(container, partition, label string) string {
	if label == "" {
		if partition == "parent" {
			return fmt.Sprintf("%s", container)
		} else {
			return fmt.Sprintf("%s/%s", container, partition)
		}
	} else {
		if partition == "parent" || partition == "all" {
			return fmt.Sprintf("%s@%s", container, label)
		} else {
			return fmt.Sprintf("%s/%s@%s", container, partition, label)
		}
	}
}

func checkPartitionName(partition string) {
	checkArgument(partition != "", "Invalid container partition")
	partitionFound := false
	for _, vol := range fs.ChildDatasets {
		if vol == partition {
			partitionFound = true
			break
		}
	}

	if partition == "parent" {
		partitionFound = true
	}
	checkArgument(partitionFound, "Invalid partition %s", partition)
}
