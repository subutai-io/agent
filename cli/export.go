package cli

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"

	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/lib/fs"
	"github.com/subutai-io/agent/log"
	"github.com/subutai-io/agent/agent/utils"
	"strings"
	"path"
	"github.com/subutai-io/agent/lib/exec"
	"strconv"
)

var (
	allsizes = []string{"tiny", "small", "medium", "large", "huge"}
)

// LxcExport sub command prepares an archive from a template config.Agent.CacheDir
// This archive can be moved to another Subutai peer and deployed as ready-to-use template or uploaded to Subutai's global template repository to make it
// widely available for others to use.
//
// Export consist of two steps if the target is a container:
// container promotion to template (see "promote" command) and packing the template into the archive.
// If already a template just the packing of the archive takes place.
//
// Configuration values for template metadata parameters can be overridden on export, like the recommended container size when the template is cloned using `-s` option.
// The template's version can also specified on export so the import command can use it to request specific versions.
//TODO update doco on site for export, import,clone

func LxcExport(name, newname, version, prefsize, token, description string, private bool, local bool) {

	if !container.IsContainer(name) {
		log.Error("Container " + name + " not found")
	}

	if token == "" {
		log.Error("Missing CDN token")
	}

	owner := getOwner(token)

	wasRunning := false
	if container.State(name) == "RUNNING" {
		LxcStop(name)
		wasRunning = true
	}

	size := "tiny"
	for _, s := range allsizes {
		if prefsize == s {
			size = prefsize
		}
	}

	parent := container.GetProperty(name, "subutai.parent")
	parentOwner := container.GetProperty(name, "subutai.parent.owner")
	parentVersion := container.GetProperty(name, "subutai.parent.version")
	parentRef := strings.Join([]string{parent, parentOwner, parentVersion}, ":")

	if strings.TrimSpace(version) == "" {
		version = parentVersion
	}

	//cleanup files
	cleanupFS(path.Join(config.Agent.LxcPrefix, name, "/var/log"), 0775)
	cleanupFS(path.Join(config.Agent.LxcPrefix, name, "/var/cache"), 0775)

	var dst string
	if newname != "" {
		dst = path.Join(config.Agent.CacheDir, newname+
			"-subutai-template_"+ version+ "_"+ runtime.GOARCH)
	} else {
		dst = path.Join(config.Agent.CacheDir, name+
			"-subutai-template_"+ version+ "_"+ runtime.GOARCH)
	}

	os.MkdirAll(dst, 0755)
	os.MkdirAll(dst+"/deltas", 0755)

	for _, vol := range []string{"rootfs", "home", "opt", "var"} {
		//remove old snapshot if any
		if fs.DatasetExists(name + "/" + vol + "@now") {
			fs.RemoveDataset(name+"/"+vol+"@now", false)
		}
		// snapshot each partition
		fs.CreateSnapshot(name + "/" + vol + "@now")

		// send incremental delta between parent and child to delta file
		fs.SendStream(parentRef+"/"+vol+"@now", name+"/"+vol+"@now", dst+"/deltas/"+vol+".delta")
	}

	//copy config files
	src := path.Join(config.Agent.LxcPrefix, name)
	fs.Copy(src+"/fstab", dst+"/fstab")
	fs.Copy(src+"/config", dst+"/config")

	//update template config
	templateConf := [][]string{
		//{"subutai.template", name},
		{"subutai.template.owner", owner},
		{"subutai.template.version", version},
		{"subutai.template.size", size},
		{"lxc.network.ipv4.gateway"},
		{"lxc.network.ipv4"},
		{"lxc.network.veth.pair"},
		{"lxc.network.hwaddr"},
		{"#vlan_id"},
	}

	if len(description) != 0 {
		templateConf = append(templateConf, []string{"subutai.template.description", "\"" + description + "\""})
	} else {
		templateConf = append(templateConf, []string{"subutai.template.description"})
	}

	if newname != "" {
		templateConf = append(templateConf, []string{"subutai.template", newname})
		templateConf = append(templateConf, []string{"lxc.utsname", newname})
		templateConf = append(templateConf, []string{"lxc.rootfs", path.Join(config.Agent.LxcPrefix, newname, "rootfs")})
		templateConf = append(templateConf, []string{"lxc.mount.entry", path.Join(config.Agent.LxcPrefix, newname, "home") + " home none bind,rw 0 0"})
		templateConf = append(templateConf, []string{"lxc.mount.entry", path.Join(config.Agent.LxcPrefix, newname, "var") + " var none bind,rw 0 0"})
		templateConf = append(templateConf, []string{"lxc.mount.entry", path.Join(config.Agent.LxcPrefix, newname, "opt") + " opt none bind,rw 0 0"})

	} else {
		templateConf = append(templateConf, []string{"subutai.template", name})
	}

	updateTemplateConfig(dst+"/config", templateConf)

	//copy template icon if any
	if _, err := os.Stat(src + "/icon.png"); !os.IsNotExist(err) {
		fs.Copy(src+"/icon.png", dst+"/icon.png")
	}

	// check: write package list to packages
	if container.State(name) != "RUNNING" {
		LxcStart(name)
	}
	pkgCmdResult, _ := container.AttachExec(name, []string{"timeout", "60", "dpkg", "-l"})
	strCmdRes := strings.Join(pkgCmdResult, "\n")
	log.Check(log.FatalLevel, "Write packages",
		ioutil.WriteFile(dst+"/packages",
			[]byte(strCmdRes), 0755))

	//archive template contents
	templateArchive := dst + ".tar.gz"
	fs.Tar(dst, templateArchive)
	log.Check(log.FatalLevel, "Removing temporary file", os.RemoveAll(dst))
	log.Info(name + " exported to " + templateArchive)

	//upload to CDN
	if !local {

		if hash, err := addToCdn(templateArchive); err != nil {
			log.Error("Failed to upload template: " + err.Error())
		} else {
			cdnFileId := strings.TrimSpace(hash)

			//cache template info since template is in CDN
			//no need to calculate signature since for locally cached info it is not checked
			var templateInfo = templ{}
			templateInfo.Id = cdnFileId
			if newname != "" {
				templateInfo.Name = newname

			} else {
				templateInfo.Name = name
			}
			templateInfo.Version = version
			templateInfo.Owner = []string{owner}
			md5Sum, err := fs.Md5Sum(templateArchive)
			log.Check(log.WarnLevel, "Getting template md5sum", err)
			templateInfo.Md5 = md5Sum
			fSize, err := fs.FileSize(templateArchive)
			log.Check(log.WarnLevel, "Getting template size", err)
			templateInfo.Size = strconv.FormatInt(fSize, 10)

			cacheTemplateInfo(templateInfo)

			//IMPORTANT: used by Console
			log.Info("Template uploaded, hash:" + templateInfo.Id + " md5:" + templateInfo.Md5 +
				" size:" + templateInfo.Size + " parent:'" + parentRef + "'")
		}

		//log.Check(log.WarnLevel, "Removing file: "+templateArchive, os.Remove(templateArchive))
	}

	if wasRunning {
		LxcStart(name)
	} else {
		LxcStop(name)
	}

}

func getOwner(token string) string {

	url := config.CDN.Kurjun + "/users/username?token=" + token

	client := utils.GetClient(config.CDN.Allowinsecure, 15)
	response, err := client.Get(url)
	log.Check(log.ErrorLevel, "Getting owner, get: "+url, err)
	defer utils.Close(response)

	if response.StatusCode != 200 {
		log.Error("Failed to get owner:  " + response.Status)
	}

	body, err := ioutil.ReadAll(response.Body)
	log.Check(log.ErrorLevel, "Reading owner ", err)
	owner := string(body)
	log.Debug("Owner is " + owner)

	return owner

}

func addToCdn(path string) (string, error) {
	return exec.ExecuteOutput("ipfs", "add", "--progress", "-Q", path)
}

func updateTemplateConfig(path string, params [][]string) error {

	cfg := container.LxcConfig{}
	err := cfg.Load(path)
	if err != nil {
		return err
	}

	cfg.SetParams(params)

	return cfg.Save()
}

// clearFile writes an empty byte array to specified file
func clearFile(path string, f os.FileInfo, ignore error) error {
	if !f.IsDir() {
		ioutil.WriteFile(path, []byte{}, 0775)
	}
	return nil
}

// cleanupFS removes files in specified path
func cleanupFS(path string, perm os.FileMode) {
	if perm == 0000 {
		os.RemoveAll(path)
	} else {
		filepath.Walk(path, clearFile)
	}
}
