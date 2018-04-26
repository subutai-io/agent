package cli

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/cheggaaa/pb.v1"
	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/lib/fs"
	"github.com/subutai-io/agent/log"
	"github.com/subutai-io/agent/agent/utils"
	"strings"
	"github.com/subutai-io/agent/lib/exec"
	"path"
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
	cleanupFS(config.Agent.LxcPrefix+name+"/var/log/", 0775)
	cleanupFS(config.Agent.LxcPrefix+name+"/var/cache", 0775)

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
		// snapshot each partition
		if !fs.DatasetExists(name + "/" + vol + "@now") {
			fs.CreateSnapshot(name + "/" + vol + "@now")
		}
		// send incremental delta between parent and child to delta file
		fs.SendStream(parentRef+"/"+vol+"@now", name+"/"+vol+"@now", dst+"/deltas/"+vol+".delta")
	}

	//copy config files
	src := config.Agent.LxcPrefix + name
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
		{"#vlan_id"}, //todo review
	}

	if len(description) != 0 {
		templateConf = append(templateConf, []string{"subutai.template.description", "\"" + description + "\""})
	} else {
		templateConf = append(templateConf, []string{"subutai.template.description"})
	}

	if newname != "" {
		templateConf = append(templateConf, []string{"subutai.template", newname})
		templateConf = append(templateConf, []string{"lxc.utsname", newname})
		templateConf = append(templateConf, []string{"lxc.rootfs", config.Agent.LxcPrefix + newname + "/rootfs"})
		templateConf = append(templateConf, []string{"lxc.mount.entry", config.Agent.LxcPrefix + newname + "/home home none bind,rw 0 0"})
		templateConf = append(templateConf, []string{"lxc.mount.entry", config.Agent.LxcPrefix + newname + "/var var none bind,rw 0 0"})
		templateConf = append(templateConf, []string{"lxc.mount.entry", config.Agent.LxcPrefix + newname + "/opt opt none bind,rw 0 0"})

	} else {
		templateConf = append(templateConf, []string{"subutai.template", name})
	}

	updateTemplateConfig(dst+"/config", templateConf)

	//copy template icon if any
	if _, err := os.Stat(src + "/icon.png"); !os.IsNotExist(err) {
		fs.Copy(src+"/icon.png", dst+"/icon.png")
	}

	//create diffs
	os.MkdirAll(dst+"/diff", 0755)
	execDiff(config.Agent.LxcPrefix+parentRef+"/rootfs", config.Agent.LxcPrefix+name+"/rootfs", dst+"/diff/rootfs.diff")
	execDiff(config.Agent.LxcPrefix+parentRef+"/home", config.Agent.LxcPrefix+name+"/home", dst+"/diff/home.diff")
	execDiff(config.Agent.LxcPrefix+parentRef+"/opt", config.Agent.LxcPrefix+name+"/opt", dst+"/diff/opt.diff")
	execDiff(config.Agent.LxcPrefix+parentRef+"/var", config.Agent.LxcPrefix+name+"/var", dst+"/diff/var.diff")

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

		if hash, err := upload(templateArchive, token, private); err != nil {
			log.Error("Failed to upload template: " + err.Error())
		} else {
			cdnFileId := string(hash)
			log.Info("Template uploaded, hash: " + cdnFileId)

			//cache template info since template is in CDN
			//no need to calculate signature since for locally cached info it is not checked

			var templateInfo = templ{}
			templateInfo.Id = cdnFileId
			if newname != "" {
				templateInfo.Name = newname
				templateInfo.File = newname + "-subutai-template_" + version + "_" + runtime.GOARCH

			} else {
				templateInfo.Name = name
				templateInfo.File = name + "-subutai-template_" + version + "_" + runtime.GOARCH
			}
			templateInfo.Version = version
			templateInfo.Owner = []string{owner}
			templateInfo.Md5 = md5sum(templateArchive)

			cacheTemplateInfo(templateInfo)
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

	url := config.CDN.Kurjun + "/auth/owner?token=" + token

	kurjun := utils.GetClient(config.CDN.Allowinsecure, 15)
	response, err := kurjun.Get(url)
	log.Check(log.ErrorLevel, "Getting owner, get: "+url, err)
	defer utils.Close(response)

	if response.StatusCode == 404 {
		log.Error("Owner not found")
	}
	if response.StatusCode != 200 {
		log.Error("Failed to get owner:  " + response.Status)
	}

	body, err := ioutil.ReadAll(response.Body)
	log.Check(log.ErrorLevel, "Reading owner, get: "+url, err)

	return string(body)

}

func upload(path, token string, private bool) ([]byte, error) {
	//check file availability
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	//check CDN availability
	utils.CheckCDN()

	body := &bytes.Buffer{}

	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("file", filepath.Base(path))
	if err != nil {
		return nil, err
	}

	_, err = io.Copy(part, file)
	if err != nil {
		return nil, err
	}

	if private {
		_ = writer.WriteField("private", "true")
	}

	err = writer.Close()
	if err != nil {
		return nil, err
	}

	// get size of file
	fi, err := file.Stat()
	if err != nil {
		return nil, err
	}

	// create and start bar
	bar := pb.New(int(fi.Size())).SetUnits(pb.U_BYTES)
	bar.Start()
	defer bar.Finish()

	// create proxy reader
	proxedBody := bar.NewProxyReader(body)

	req, err := http.NewRequest("POST", config.CDN.Kurjun+"/template/upload", proxedBody)
	if err != nil {
		return nil, err
	}

	//set headers
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("token", token)

	client := utils.GetClientForUploadDownload()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer utils.Close(resp)

	if resp.StatusCode != http.StatusOK {
		out, err := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP status: %s; %s; %v", resp.Status, out, err)
	}

	return ioutil.ReadAll(resp.Body)
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

// execDiff executes `diff` command for specified directories and writes command output
func execDiff(dir1, dir2, output string) {
	out, _ := exec.Execute("diff", "-Nur", dir1, dir2)
	err := ioutil.WriteFile(output, []byte(out), 0600)
	log.Check(log.FatalLevel, "Writing diff to file"+output, err)
}

// clearFile writes an empty byte array to specified file
func clearFile(path string, f os.FileInfo, err error) error {
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
