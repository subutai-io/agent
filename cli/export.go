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

	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/lib/fs"
	"github.com/subutai-io/agent/log"
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
func LxcExport(name, version, prefsize, token string, private bool) {
	size := "tiny"
	for _, s := range allsizes {
		if prefsize == s {
			size = prefsize
		}
	}
	srcver := container.GetConfigItem(config.Agent.LxcPrefix+name+"/config", "subutai.template.version")
	if len(version) == 0 {
		version = srcver
	}
	dst := config.Agent.LxcPrefix + "tmpdir/" + name +
		"-subutai-template_" + version + "_" + runtime.GOARCH

	if !container.IsTemplate(name) {
		LxcPromote(name)
	}
	// check: parent is template
	parent := container.GetParent(name)
	if !container.IsTemplate(parent) {
		log.Error("Parent " + parent + " is not a template")
	}

	os.MkdirAll(dst, 0755)
	os.MkdirAll(dst+"/deltas", 0755)
	os.MkdirAll(dst+"/diff", 0755)

	for _, vol := range []string{"rootfs", "home", "opt", "var"} {
		err := fs.Send(config.Agent.LxcPrefix+parent+"/"+vol, config.Agent.LxcPrefix+name+"/"+vol, dst+"/deltas/"+vol+".delta")
		log.Check(log.FatalLevel, "Sending delta "+dst+"/deltas/"+vol+".delta", err)
	}

	// changeConfigFile(name, packageVersion, dst)
	container.SetContainerConf(name, [][]string{
		{"subutai.template.package", dst + ".tar.gz"},
		{"subutai.template.version", version},
		{"subutai.template.size", size},
	})

	src := config.Agent.LxcPrefix + name
	fs.Copy(src+"/fstab", dst+"/fstab")
	fs.Copy(src+"/config", dst+"/config")
	fs.Copy(src+"/packages", dst+"/packages")
	if parent != name {
		fs.Copy(src+"/diff/var.diff", dst+"/diff/var.diff")
		fs.Copy(src+"/diff/opt.diff", dst+"/diff/opt.diff")
		fs.Copy(src+"/diff/home.diff", dst+"/diff/home.diff")
		fs.Copy(src+"/diff/rootfs.diff", dst+"/diff/rootfs.diff")
	}

	container.SetContainerConf(name, [][]string{
		{"subutai.template.package", config.Agent.LxcPrefix + "tmpdir/" + name +
			"-subutai-template_" + srcver + "_" + runtime.GOARCH + ".tar.gz"},
		{"subutai.template.version", srcver},
	})

	fs.Tar(dst, dst+".tar.gz")
	log.Check(log.FatalLevel, "Remove tmpdir", os.RemoveAll(dst))
	log.Info(name + " exported to " + dst + ".tar.gz")
	if len(token) > 0 {
		if hash, err := upload(dst+".tar.gz", token, private); err != nil {
			log.Error("Failed to upload template: " + err.Error())
		} else {
			log.Info("Template uploaded, hash: " + string(hash))
		}
	}
}

func upload(path, token string, private bool) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

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
	_ = writer.WriteField("token", token)

	err = writer.Close()
	if err != nil {
		return nil, err
	}

	config.CheckKurjun()

	req, err := http.NewRequest("POST", config.CDN.Kurjun+"/template/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if err != nil {
		return nil, err
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		out, err := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP status: %s; %s; %v", resp.Status, out, err)
	}

	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}
