package cli

import (
	"fmt"
	"strconv"

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
//todo improve, remove threshold param since alerts are not used
func LxcQuota(name, res, size, threshold string) {
	if len(threshold) > 0 {
		setQuotaThreshold(name, res, threshold)
	}
	quota := "0"
	alert := getQuotaThreshold(name, res)
	switch res {
	case "network":
		quota = container.QuotaNet(name, size)
	case "disk":
		if len(size) > 0 {
			vs, _ := strconv.Atoi(size)
			fs.SetQuota(name, vs)
		}
		vr, _ := fs.GetQuota(name)
		//convert bytes to GB
		vr /= 1024 * 1024 * 1024
		quota = strconv.Itoa(vr)
	case "cpuset":
		quota = container.QuotaCPUset(name, size)
	case "ram":
		quota = strconv.Itoa(container.QuotaRAM(name, size))
	case "cpu":
		quota = strconv.Itoa(container.QuotaCPU(name, size))
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
	if size := container.GetProperty(name, res); len(size) > 0 {
		return size
	}
	return "0"
}
