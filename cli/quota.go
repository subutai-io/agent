package cli

import (
	"fmt"
	"strconv"

	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/db"
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/lib/fs"
	"github.com/subutai-io/agent/log"
)

// LxcQuota function controls container's quotas and thresholds. Available resources:
//	cpu, %
//	cpuset, available cores
//	ram, Mb
//	network, Kbps
//	rootfs/home/var/opt, Gb
// The threshold value represents a percentage for each resource. Once resource consumption exceeds this threshold it triggers an alert.
// The clone operation, sets no quotas and thresholds for new containers; quotas need to be configured with quota command after a clone operation.
func LxcQuota(name, res, size, threshold string) {
	if len(threshold) > 0 {
		setQuotaThreshold(name, res, threshold)
	}
	quota := "0"
	alert := getQuotaThreshold(name, res)
	switch res {
	case "network":
		quota = container.QuotaNet(name, size)
	case "rootfs", "home", "var", "opt":
		quota = fs.Quota(name+"/"+res, size)
	case "disk":
		quota = fs.DiskQuota(name, size)
	case "cpuset":
		quota = container.QuotaCPUset(name, size)
	case "ram":
		quota = strconv.Itoa(container.QuotaRAM(name, size))
	case "cpu":
		quota = strconv.Itoa(container.QuotaCPU(name, size))
	}
	if len(res) > 0 && len(size) > 0 {
		bolt, err := db.New()
		log.Check(log.WarnLevel, "Opening database", err)
		log.Check(log.WarnLevel, "Writing continer data to database", bolt.ContainerQuota(name, res, size))
		log.Check(log.WarnLevel, "Closing database", bolt.Close())
	}

	if quota == "none" {
		quota = "0"
	}

	fmt.Println(`{"quota":"` + quota + `", "threshold":` + alert + `}`)
}

// setQuotaThreshold sets threshold for quota alerts
func setQuotaThreshold(name, resource, size string) {
	if resource == "rootfs" || resource == "var" || resource == "opt" || resource == "home" {
		container.SetContainerConf(name, [][]string{{"subutai.alert.disk." + resource, size}})
		return
	} else if resource == "cpu" || resource == "ram" {
		container.SetContainerConf(name, [][]string{{"subutai.alert." + resource, size}})
		return
	}
	log.Fatal("Failed to set threshold for " + resource)
}

// getQuotaThreshold gets threshold of quota alerts
func getQuotaThreshold(name, resource string) string {
	res := "subutai.alert.disk." + resource
	if resource == "cpu" || resource == "ram" {
		res = "subutai.alert." + resource
	}
	if size := container.GetConfigItem(config.Agent.LxcPrefix+name+"/config", res); len(size) > 0 {
		return size
	}
	return "0"
}
