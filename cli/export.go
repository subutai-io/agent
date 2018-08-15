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
	"regexp"
	"encoding/json"
	"mime/multipart"
	"gopkg.in/cheggaaa/pb.v1"
	"io"
	"fmt"
	"net/http"
	"time"
	"sync"
)

var (
	allsizes  = []string{"tiny", "small", "medium", "large", "huge"}
	versionRx = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
)

// LxcExport sub command prepares an archive from a template config.Agent.CacheDir
// This archive can be moved to another Subutai peer and deployed as ready-to-use template or uploaded to Subutai's global template repository to make it
// widely available for others to use.
// Configuration values for template metadata parameters can be overridden on export, like the recommended container size when the template is cloned using `-s` option.
// The template's version can also specified on export so the import command can use it to request specific versions.

func LxcExport(name, newname, version, prefsize, token string, local bool) {
    //check new template name
    if newname != "" {
        utils.VerifyLxcName(newname)
    }

	if !container.IsContainer(name) {
		log.Error("Container " + name + " not found")
	}

	if token == "" {
		log.Error("Missing CDN token")
	}

	version = strings.TrimSpace(version)

	if version != "" && !versionRx.MatchString(version) {
		log.Error("Version must be in form X.Y.Z")
	}

	owner := getOwner(token)

	parent := container.GetProperty(name, "subutai.parent")
	parentOwner := container.GetProperty(name, "subutai.parent.owner")
	parentVersion := container.GetProperty(name, "subutai.parent.version")
	parentRef := strings.Join([]string{parent, parentOwner, parentVersion}, ":")

	if version == "" {
		version = parentVersion
	}

	//check template reference uniqueness
	var theOwner string = owner
	var theVersion string = version
	var theName string
	if newname != "" {
		theName = newname
	} else {
		theName = name
	}

	if templateExists(theName, theOwner, theVersion) {
		log.Error(fmt.Sprintf("Template %s@%s:%s already exists on CDN", theName, theOwner, theVersion))
	}

	wasRunning := false
	if container.State(name) == "RUNNING" {
		LxcStop(name)
		wasRunning = true
	}

	//preferred size
	pSize := "tiny"
	for _, s := range allsizes {
		if prefsize == s {
			pSize = prefsize
		}
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

	for _, vol := range fs.ChildDatasets {
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
		{"subutai.template.owner", owner},
		{"subutai.template.version", version},
		{"subutai.template.size", pSize},
		{"lxc.network.ipv4.gateway"},
		{"lxc.network.ipv4"},
		{"lxc.network.veth.pair"},
		{"lxc.network.hwaddr"},
		{"lxc.network.mtu"},
		{"#vlan_id"},
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
	fs.Compress(dst, templateArchive)
	log.Check(log.FatalLevel, "Removing temporary file", os.RemoveAll(dst))
	log.Info(name + " exported to " + templateArchive)

	//generate template metadata
	var templateInfo = Template{}
	if newname != "" {
		templateInfo.Name = newname

	} else {
		templateInfo.Name = name
	}
	md5Sum, err := fs.Md5Sum(templateArchive)
	log.Check(log.WarnLevel, "Getting template md5sum", err)
	fSize, err := fs.FileSize(templateArchive)
	log.Check(log.WarnLevel, "Getting template size", err)
	templateInfo.Version = version
	templateInfo.Owner = owner
	templateInfo.MD5 = md5Sum
	templateInfo.Size = fSize
	templateInfo.Parent = parentRef
	templateInfo.PrefSize = pSize

	//upload to CDN
	if !local {
		if err := upload(templateArchive, token); err != nil {
			log.Error("Failed to upload template: " + err.Error())
		} else {
			//IMPORTANT: used by Console
			log.Info("Template uploaded")
		}
	} else {
		templateJson, _ := json.Marshal(templateInfo)
		log.Info("Template exported, " + string(templateJson))
	}

	if wasRunning {
		LxcStart(name)
	} else {
		LxcStop(name)
	}

}

func templateExists(name, owner, version string) bool {
	theUrl := config.CdnUrl + "/template?name=" + name + "&owner=" + owner + "&version=" + version

	clnt := utils.GetClient(config.CDN.AllowInsecure, 30)
	resp, err := clnt.Get(theUrl)

	log.Check(log.ErrorLevel, "Checking template", err)

	defer utils.Close(resp)

	if resp.StatusCode == http.StatusOK {
		return true
	}

	return false
}

func getOwner(token string) string {

	theUrl := config.CdnUrl + "/users/username?token=" + token

	clnt := utils.GetClient(config.CDN.AllowInsecure, 30)

	response, err := utils.RetryGet(theUrl, clnt, 3)

	log.Check(log.ErrorLevel, "Getting owner, get: "+theUrl, err)
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

func upload(template, token string) error {

	file, err := os.Open(template)
	if log.Check(log.DebugLevel, "Opening template for upload", err) {
		return err
	}
	defer file.Close()

	fStat, err := file.Stat()
	if log.Check(log.DebugLevel, "Getting template size", err) {
		return err
	}

	bar := pb.New64(fStat.Size()).SetUnits(pb.U_BYTES).SetRefreshRate(time.Millisecond * 10)
	bar.Start()
	defer bar.Finish()

	r, w := io.Pipe()
	mpw := multipart.NewWriter(w)
	wg := sync.WaitGroup{}
	wg.Add(1)

	//feed file in a routine
	go func() {
		var part io.Writer
		defer wg.Done()
		defer bar.Finish()
		defer file.Close()
		defer w.Close()

		if err = mpw.WriteField("token", token); err != nil {
			w.CloseWithError(err)
		}

		if part, err = mpw.CreateFormFile("file", fStat.Name()); err != nil {
			w.CloseWithError(err)
		}
		part = io.MultiWriter(part, bar)
		if _, err = io.Copy(part, file); err != nil {
			w.CloseWithError(err)
		}
		if err = mpw.Close(); err != nil {
			w.CloseWithError(err)
		}
	}()

	resp, err := http.Post(config.CdnUrl+"/uploadTemplate", mpw.FormDataContentType(), r)

	wg.Wait()

	if log.Check(log.DebugLevel, "Uploading template", err) {
		return err
	}
	defer utils.Close(resp)

	out, err := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP status: %s; %s; %v", resp.Status, out, err)
	} else {
		log.Debug(string(out))
	}

	return nil
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
