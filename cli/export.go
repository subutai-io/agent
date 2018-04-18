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
)

var (
	allsizes = []string{"tiny", "small", "medium", "large", "huge"}
)

// cfg declared in promote.go

// LxcExport sub command prepares an archive from a template in the `/mnt/lib/lxc/tmpdir/` path.
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
func LxcExport(name, version, prefsize, token, description string, private bool, local bool) {
	if token == "" {
		log.Error("Missing CDN token")
	}

	owner := getOwner(token)

	size := "tiny"
	for _, s := range allsizes {
		if prefsize == s {
			size = prefsize
		}
	}
	srcver := container.GetConfigItem(config.Agent.LxcPrefix+name+"/config", "subutai.template.version")
	if strings.TrimSpace(version) == "" {
		version = srcver
	}
	dst := config.Agent.LxcPrefix + "tmpdir/" + name +
		"-subutai-template_" + version + "_" + runtime.GOARCH

	// check: parent is template
	parent := container.GetParent(name)
	if !container.IsTemplate(parent) {
		log.Error("Parent " + parent + " is not a template")
	}

	if !container.IsTemplate(name) {
		LxcPromote(name, "")
	}

	os.MkdirAll(dst, 0755)
	os.MkdirAll(dst+"/deltas", 0755)
	os.MkdirAll(dst+"/diff", 0755)

	for _, vol := range []string{"rootfs", "home", "opt", "var"} {
		// snapshot each partition
		fs.CreateSnapshot(name + "/" + vol + "@export")
		// send incremental delta between parent and child to delta file
		fs.SendStream(parent+"/"+vol+"@now", name+"/"+vol+"@export", dst+"/deltas/"+vol+".delta")
		// destroy snapshots
		fs.RemoveDataset(name+"/"+vol+"@export", false)
	}

	src := config.Agent.LxcPrefix + name
	fs.Copy(src+"/fstab", dst+"/fstab")
	fs.Copy(src+"/packages", dst+"/packages")
	if _, err := os.Stat(src + "/icon.png"); !os.IsNotExist(err) {
		fs.Copy(src+"/icon.png", dst+"/icon.png")
	}
	if parent != name {
		fs.Copy(src+"/diff/var.diff", dst+"/diff/var.diff")
		fs.Copy(src+"/diff/opt.diff", dst+"/diff/opt.diff")
		fs.Copy(src+"/diff/home.diff", dst+"/diff/home.diff")
		fs.Copy(src+"/diff/rootfs.diff", dst+"/diff/rootfs.diff")
	}

	containerConf := [][]string{
		{"subutai.template.package", dst + ".tar.gz"},
		{"subutai.template.owner", owner},
		{"subutai.template.version", version},
		{"subutai.template.size", size},
		{"subutai.template.package", config.Agent.LxcPrefix + "tmpdir/" + name +
			"-subutai-template_" + version + "_" + runtime.GOARCH + ".tar.gz"},
	}

	if len(description) != 0 {
		containerConf = append(containerConf, []string{"subutai.template.description", "\"" + description + "\""})
	}

	container.SetContainerConf(name, containerConf)

	fs.Copy(src+"/config", dst+"/config")

	templateArchive := dst + ".tar.gz"
	fs.Tar(dst, templateArchive)
	log.Check(log.FatalLevel, "Remove tmpdir", os.RemoveAll(dst))
	log.Info(name + " exported to " + templateArchive)

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
			templateInfo.Name = name
			templateInfo.Version = version
			templateInfo.Owner = []string{owner}
			templateInfo.File = name + "-subutai-template_" + version + "_" + runtime.GOARCH
			templateInfo.Md5 = md5sum(templateArchive)

			cacheTemplateInfo(templateInfo)
		}

		log.Check(log.WarnLevel, "Removing file: "+templateArchive, os.Remove(templateArchive))
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
