// Package alert is responsible for resource usage tracking, quota threshold checking and alerting triggers
package alert

import (
	"bufio"
	"io/ioutil"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/subutai-io/agent/agent/container"
	"github.com/subutai-io/agent/config"
	cont "github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/lib/fs"
)

type values struct {
	Current int `json:"current,omitempty"`
	Quota   int `json:"quota,omitempty"`
}

//Load describes container usage stats. If alert active for this container the Management server receives this data.
type Load struct {
	Container string  `json:"id,omitempty"`
	CPU       *values `json:"cpu,omitempty"`
	RAM       *values `json:"ram,omitempty"`
	Disk      *values `json:"hdd,omitempty"`
}

var (
	cpu   = make(map[string][]int)
	stats = make(map[string]Load)
)

func read(path string) (int, error) {
	out, err := ioutil.ReadFile(path)
	if err != nil {
		return -1, err
	}
	return strconv.Atoi(strings.TrimSpace(string(out)))
}

func ramMax() (int, error) {
	file, err := os.Open("/sys/fs/cgroup/memory/memory.stat")
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(bufio.NewReader(file))
	for scanner.Scan() {
		line := strings.Fields(scanner.Text())
		if len(line) > 1 && line[0] == "hierarchical_memory_limit" {
			return strconv.Atoi(strings.TrimSpace(line[1]))
		}
	}
	return 0, nil
}

func ramQuota(cont string) []int {
	u, err := read("/sys/fs/cgroup/memory/lxc/" + cont + "/memory.usage_in_bytes")
	if err != nil {
		return nil
	}

	l, err := read("/sys/fs/cgroup/memory/lxc/" + cont + "/memory.limit_in_bytes")
	if err != nil {
		return nil
	}

	var ramUsage = []int{0, l / 1024 / 1024}
	if l != 0 {
		ramUsage[0] = u * 100 / l
	}

	if mlimit, err := ramMax(); err == nil && l == mlimit {
		ramUsage[1] = 0
	}
	return ramUsage
}

func quotaCPU(name string) int {
	cfsPeriod := 100000
	cfsQuotaUs, err := ioutil.ReadFile("/sys/fs/cgroup/cpu,cpuacct/lxc/" + name + "/cpu.cfs_quota_us")
	if err != nil {
		return -1
	}

	quota, err := strconv.Atoi(strings.TrimSpace(string(cfsQuotaUs)))
	if err != nil {
		return -1
	}

	return quota * 100 / cfsPeriod / runtime.NumCPU()
}

func cpuLoad(cont string) []int {
	avgload := []int{0, quotaCPU(cont)}
	if len(cpu[cont]) == 0 {
		cpu[cont] = []int{0, 0, 0, 0, 0}
	}
	ticks, err := ioutil.ReadFile("/sys/fs/cgroup/cpuacct/lxc/" + cont + "/cpuacct.stat")
	if err != nil {
		return avgload
	}

	tick := strings.Fields(string(ticks))
	if len(tick) != 4 {
		return avgload
	}

	usertick, err := strconv.Atoi(tick[1])
	if err != nil {
		return avgload
	}

	systick, err := strconv.Atoi(tick[3])
	if err != nil {
		return avgload
	}

	cpu[cont] = append([]int{usertick + systick}, cpu[cont][0:4]...)
	if cpu[cont][4] == 0 {
		return avgload
	}
	avgload[0] = (cpu[cont][0] - cpu[cont][4]) / runtime.NumCPU() / 20
	if avgload[1] != 0 {
		avgload[0] = avgload[0] * 100 / avgload[1]
	}
	return avgload
}

//returns disk usage in % and quota in GB
func diskUsage(path string) []int {
	bytesUsed, err := fs.DatasetDiskUsage(path)
	if err != nil {
		bytesUsed = 0
	}

	quota, err := fs.GetQuota(path)
	if err != nil {
		quota = 0
	}

	diskUsage := 0
	if quota != 0 {
		diskUsage = bytesUsed * 100 / quota
	}

	return []int{diskUsage, quota / (1024 * 1024 * 1024)}
}

//Processing works as a daemon, collecting information about containers stats and preparing list of active alerts.
func Processing() {
	for {
		stats = alertLoad()
		for k := range cpu {
			if _, ok := stats[k]; !ok {
				delete(cpu, k)
			}
		}
		time.Sleep(time.Second * 30)
	}
}

func alertLoad() (load map[string]Load) {
	load = make(map[string]Load)

	files, err := ioutil.ReadDir("/sys/fs/cgroup/cpu/lxc/")
	if err != nil {
		return
	}

	for _, con := range files {
		if !con.IsDir() {
			continue
		}

		cpuValues := cpuLoad(con.Name())
		ramValues := ramQuota(con.Name())
		diskValues := diskUsage(con.Name())

		if len(cpuValues) > 1 && len(ramValues) > 1 && len(diskValues) > 1 {
			load[con.Name()] = Load{
				CPU:  &values{Current: cpuValues[0], Quota: cpuValues[1]},
				RAM:  &values{Current: ramValues[0], Quota: ramValues[1]},
				Disk: &values{Current: diskValues[0], Quota: diskValues[1]},
			}
		}
	}

	return load
}

//Current return the list of active alerts. It will be used in heartbeat to notify the Management server.
func Current(list []container.Container) []Load {
	var loadList []Load
	for _, v := range list {
		var item Load

		threshold, err := strconv.Atoi(cont.GetConfigItem(config.Agent.LxcPrefix+v.Name+"/config", "subutai.alert.cpu"))
		if threshold > 0 && stats[v.Name].CPU != nil && stats[v.Name].CPU.Current > threshold && err == nil {
			item.CPU = &values{Current: stats[v.Name].CPU.Current, Quota: stats[v.Name].CPU.Quota}
		}

		threshold, err = strconv.Atoi(cont.GetConfigItem(config.Agent.LxcPrefix+v.Name+"/config", "subutai.alert.ram"))
		if threshold > 0 && stats[v.Name].RAM != nil && stats[v.Name].RAM.Current > threshold && err == nil {
			item.RAM = &values{Current: stats[v.Name].RAM.Current, Quota: stats[v.Name].RAM.Quota}
		}

		if item.CPU != nil || item.RAM != nil {
			item.Container = v.ID
			loadList = append(loadList, item)
		}
	}
	return loadList
}

func Quota(list []container.Container) (output []container.Container) {
	for _, v := range list {
		if c, ok := stats[v.Name]; ok {
			v.Quota.CPU = c.CPU.Quota
			v.Quota.RAM = c.RAM.Quota
			v.Quota.Disk = stats[v.Name].Disk.Quota
		}
		output = append(output, v)
	}
	return
}
