package cli

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"code.cloudfoundry.org/archiver/extractor"
	"github.com/nightlyone/lockfile"
	"gopkg.in/cheggaaa/pb.v1"

	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/db"
	"github.com/subutai-io/agent/lib/container"
	"github.com/subutai-io/agent/lib/gpg"
	"github.com/subutai-io/agent/lib/template"
	"github.com/subutai-io/agent/log"
	"github.com/subutai-io/agent/agent/utils"
	"github.com/mcuadros/go-version"
	"github.com/subutai-io/agent/lib/fs"
	"runtime"
)

var (
	owners = []string{"subutai", "jenkins", "docker", ""}
)

type templ struct {
	name      string
	file      string
	version   string
	branch    string
	id        string
	md5       string
	owner     []string
	signature map[string]string
}

type metainfo struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Owner   []string          `json:"owner"`
	Version string            `json:"version"`
	File    string            `json:"filename"`
	Signs   map[string]string `json:"signature"`
	Hash struct {
		Md5    string
		Sha256 string
	} `json:"hash"`
}

// getTemplateInfoById retrieves template name from global repository by passed id string
func getTemplateInfoById(t *templ, id string, token string) {
	//Since only kurjun knows template's ID, we cannot define if we have template already installed in system by ID as we do it by name, so unreachable kurjun in this case is a deadend for us
	//To omit this issue we should add ID into template config and use this ID as a "primary key" to any request
	url := config.CDN.Kurjun + "/template/info?id=" + id + "&token=" + token

	kurjun := utils.GetClient(config.CDN.Allowinsecure, 15)
	response, err := kurjun.Get(url)
	log.Check(log.ErrorLevel, "Retrieving template info, get: "+url, err)
	defer utils.Close(response)

	if response.StatusCode == 404 {
		log.Error("Template " + t.name + " not found")
	}
	if response.StatusCode != 200 {
		log.Error("Failed to get template info:  " + response.Status)
	}

	body, err := ioutil.ReadAll(response.Body)
	log.Check(log.ErrorLevel, "Reading template info, get: "+url, err)

	var meta []metainfo
	if log.Check(log.WarnLevel, "Parsing response body", json.Unmarshal(body, &meta)) || len(meta) == 0 {
		log.Error("Failed to parse template info:  " + response.Status)
	}

	t.name = meta[0].Name
	t.owner = meta[0].Owner
	t.version = meta[0].Version
	t.id = meta[0].ID
	t.file = meta[0].File
	t.md5 = meta[0].Hash.Md5
	t.signature = meta[0].Signs

}

func getTemplateInfo(template string, kurjToken string) templ {

	var t templ

	if id := strings.Split(template, "id:"); len(id) > 1 {
		templateId := id[1]

		bolt, err := db.New()
		log.Check(log.WarnLevel, "Opening database", err)
		meta := bolt.TemplateByName(templateId)
		log.Check(log.WarnLevel, "Closing database", bolt.Close())

		if meta != nil {
			templateInfo, found := meta["templateInfo"]
			if found {
				var t templ
				err := json.Unmarshal([]byte(templateInfo), &t)
				if err == nil {
					return t
				}
			}
		}

		utils.CheckCDN()

		getTemplateInfoById(&t, templateId, kurjToken)

	} else {
		utils.CheckCDN()

		// full template reference is template@owner:version e.g. master@subutai:4.0.0
		// if owner is missing then we use verified only, if version is missing we use latest version

		if templateNameNOwnerNVersionRx.MatchString(template) {
			groups := utils.MatchRegexGroups(templateNameNOwnerNVersionRx, template)

			getTemplateInfoByName(&t, groups["name"], groups["owner"], groups["version"], kurjToken)
		} else if templateNameNOwnerRx.MatchString(template) {
			groups := utils.MatchRegexGroups(templateNameNOwnerRx, template)

			getTemplateInfoByName(&t, groups["name"], groups["owner"], "", kurjToken)
		} else if templateNameRx.MatchString(template) {
			groups := utils.MatchRegexGroups(templateNameRx, template)

			getTemplateInfoByName(&t, groups["name"], "", "", kurjToken)
		} else {
			log.Error("Invalid template name " + template)
		}

	}

	verifySignature(t)

	log.Info("Version: " + t.version)

	return t
}

//TODO urlEncode the kurjun URL
func getTemplateInfoByName(t *templ, name string, owner string, version string, token string) {
	//Since only kurjun knows template's ID, we cannot define if we have template already installed in system by ID as we do it by name, so unreachable kurjun in this case is a deadend for us
	//To omit this issue we should add ID into template config and use this ID as a "primary key" to any request

	url := config.CDN.Kurjun + "/template/info?name=" + name

	if owner == "" {
		url += "&verified=true"
	} else {
		url += "&owner=" + owner
	}

	if version == "" {
		url += "&version=latest"
	} else {
		url += "&version=" + version
	}

	if token != "" {
		url += "&token=" + token
	}

	kurjun := utils.GetClient(config.CDN.Allowinsecure, 15)
	response, err := kurjun.Get(url)
	log.Check(log.ErrorLevel, "Retrieving template info, get: "+url, err)
	defer utils.Close(response)

	if response.StatusCode == 404 {
		log.Error("Template " + t.name + " not found")
	}
	if response.StatusCode != 200 {
		log.Error("Failed to get template info:  " + response.Status)
	}

	body, err := ioutil.ReadAll(response.Body)
	log.Check(log.ErrorLevel, "Reading template info, get: "+url, err)

	var meta []metainfo
	if log.Check(log.WarnLevel, "Parsing response body", json.Unmarshal(body, &meta)) || len(meta) == 0 {
		log.Error("Failed to parse template info:  " + response.Status)
	}

	t.name = meta[0].Name
	t.owner = meta[0].Owner
	t.version = meta[0].Version
	t.id = meta[0].ID
	t.file = meta[0].File
	t.md5 = meta[0].Hash.Md5
	t.signature = meta[0].Signs

}

// md5sum returns MD5 hash sum of specified file
func md5sum(filePath string) string {
	file, err := os.Open(filePath)
	if err != nil {
		return ""
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return ""
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func downloadWithRetry(t templ, token string, retry int) bool {

	if len(t.id) == 0 {
		return false
	}

	for c := 0; c < retry; c++ {
		ok, err := download(t, token)
		if err == nil {
			return ok
		} else {
			log.Check(log.WarnLevel, "Download interrupted, retrying", err)
		}
	}

	return false
}

// download gets template archive from global repository
func download(t templ, token string) (bool, error) {

	out, err := os.Create(config.Agent.LxcPrefix + "tmpdir/" + t.file)
	if err != nil {
		log.Debug("Failed to create archive ", err)
		return false, err
	}
	defer out.Close()

	client := utils.GetClientForUploadDownload()

	url := config.CDN.Kurjun + "/template/download?id=" + t.id + "&token=" + token

	log.Debug("Template url " + url)

	response, err := client.Get(url)
	if err != nil {
		log.Debug("Failed to connect to Kurjun ", err)
		return false, err
	}
	defer utils.Close(response)

	bar := pb.New(int(response.ContentLength)).SetUnits(pb.U_BYTES)
	if response.ContentLength <= 0 {
		bar.NotPrint = true
	}
	bar.Start()
	rd := bar.NewProxyReader(response.Body)
	defer bar.Finish()
	_, err = io.Copy(out, rd)
	if err != nil {
		log.Debug("Failed to download template ", err)
		return false, err
	}

	hash := md5sum(config.Agent.LxcPrefix + "tmpdir/" + t.file)
	if t.md5 == hash {
		return true, nil
	}

	log.Warn("Hash sum mismatch")

	return false, err
}

// lockSubutai creates lock file for period of import for certain template to prevent conflicts during write operation
func lockSubutai(file string) (lockfile.Lockfile, error) {
	lock, err := lockfile.New("/var/run/lock/subutai." + file)
	if log.Check(log.DebugLevel, "Init lock "+file, err) {
		return lock, err
	}

	err = lock.TryLock()
	if log.Check(log.DebugLevel, "Locking file "+file, err) {
		if p, err2 := lock.GetOwner(); err2 == nil {
			cmd, err2 := ioutil.ReadFile(fmt.Sprintf("/proc/%v/cmdline", p.Pid))
			if err2 != nil || !(strings.Contains(string(cmd), "subutai") && strings.Contains(string(cmd), "import")) {
				log.Check(log.DebugLevel, "Removing broken lockfile /var/run/lock/subutai."+file, os.Remove("/var/run/lock/subutai."+file))
			}
		}
		return lock, err
	}

	return lock, nil
}

// LxcImport function deploys a Subutai template on a Resource Host. The import algorithm works with both the global template repository and a local directory
// to provide more flexibility to enable working with published and custom local templates. Official published templates in the global repository have a overriding scope
// over custom local artifacts if there's any template naming conflict.
//
// If Internet access is lost, or it is not possible to upload custom templates to the repository, the filesystem path `/var/snap/subutai/common/lxc/tmpdir/` could be used as local repository;
// the import sub command checks this directory if a requested published template or the global repository is not available.
//
// The import binding handles security checks to confirm the authenticity and integrity of templates. Besides using strict SSL connections for downloads,
// it verifies the fingerprint and its checksum for each template: an MD5 hash sum signed with author's GPG key. Import executes different integrity and authenticity checks of the template
// transparent to the user to protect system integrity from all possible risks related to template data transfers over the network.
//
// The repository supports public, group private (shared), and private files. Import without specifying a security token can only access public templates.
//
// `subutai import management` is a special operation which differs from the import of other templates. Besides the usual template deployment operations,
// "import management" demotes the template, starts its container, transforms the host network, and forwards a few host ports, etc.

func LxcImport(name, token string, local bool, auxDepList ...string) {
	var err error

	if container.ContainerOrTemplateExists(name) && name == "management" && len(token) > 1 {
		gpg.ExchageAndEncrypt("management", token)
		return
	}

	var t templ
	t.name = name

	if !local {
		t = getTemplateInfo(t.name, token)
	}

	log.Info("Importing " + t.name)

	var lock lockfile.Lockfile
	for lock, err = lockSubutai(t.name + ".import"); err != nil; lock, err = lockSubutai(t.name + ".import") {
		time.Sleep(time.Second * 1)
	}
	defer lock.Unlock()

	isTemplate := container.IsTemplate(t.name)
	if isTemplate {

		if local {
			log.Info(t.name + " instance exists")
			return
		}

		existingVersion := container.GetConfigItem(config.Agent.LxcPrefix+t.name+"/config", "subutai.template.version")

		//latest version is already installed
		if version.Compare(t.version, existingVersion, "<=") {
			log.Info(t.name + " instance exists")
			return
		}
	} else if container.IsContainer(t.name) {
		log.Info(t.name + " instance exists")
		return
	}

	wildcardTemplateName := config.Agent.LxcPrefix + "tmpdir/" +
		strings.ToLower(t.name) + "-subutai-template_*_" + strings.ToLower(runtime.GOARCH) + ".tar.gz"

	var archiveExists = false

	if local {
		//check if template with the same name but any version exists locally
		files := fs.GetFilesWildCard(wildcardTemplateName)

		//figure out latest version among locally present ones
		if files != nil && len(files) > 0 {

			latestVersionFile := files[0]
			latestVersion := getVersion(latestVersionFile)

			for idx, file := range files {
				if idx > 0 {
					ver := getVersion(file)
					if version.Compare(ver, latestVersion, ">") {
						latestVersionFile = file
						latestVersion = ver
					}
				}
			}

			t.file = strings.Replace(latestVersionFile, config.Agent.LxcPrefix+"tmpdir/", "", 1)

			archiveExists = true

		} else {
			log.Warn("Template " + t.name + " not found in local cache")

			//since we failed to find a local archive
			//obtain template metadata from CDN
			//to allow further download from CDN
			t = getTemplateInfo(t.name, token)
		}

	} else {

		archiveExists = fs.FileExists(config.Agent.LxcPrefix + "tmpdir/" + t.file)
	}

	if archiveExists {

		log.Debug("Template archive is present in local cache")

		if !local {
			hash := md5sum(config.Agent.LxcPrefix + "tmpdir/" + t.file)
			if t.md5 == hash {

				log.Debug("File integrity is verified")
			} else {

				log.Warn("File integrity verification failed")

				//make agent re-download verified template from CDN
				archiveExists = false
			}
		} else {
			log.Warn("Skipping file integrity verification since -local flag was passed")
		}

		//clean all matching OLDER archives
		fs.DeleteFilesWildcard(wildcardTemplateName, t.file)
	} else {

		log.Debug("Template archive is missing in local cache")

		//clean all matching archives
		fs.DeleteFilesWildcard(wildcardTemplateName)
	}

	if !archiveExists {
		log.Info("Downloading " + t.name)

		downloaded := false

		if len(t.owner) == 0 {
			for _, owner := range owners {
				if t.owner = []string{owner}; len(owner) == 0 {
					t.owner = []string{}
				}
				if downloadWithRetry(t, token, 5) {
					downloaded = true
					break
				}
			}
		}

		if !downloaded && !downloadWithRetry(t, token, 5) {

			log.Error("Failed to download or verify template " + t.name)
		} else {

			log.Info("File integrity is verified")
		}
	}

	//remove old template before installing new one
	if isTemplate {
		container.DestroyTemplate(t.name)
	}

	log.Info("Unpacking template " + t.name)
	log.Debug(config.Agent.LxcPrefix + "tmpdir/" + t.file + " to " + t.name)
	tgz := extractor.NewTgz()
	templdir := config.Agent.LxcPrefix + "tmpdir/" + t.name
	log.Check(log.FatalLevel, "Extracting tgz", tgz.Extract(config.Agent.LxcPrefix+"tmpdir/"+t.file, templdir))
	parent := container.GetConfigItem(templdir+"/config", "subutai.parent")
	parentOwner := container.GetConfigItem(templdir+"/config", "subutai.parent.owner")
	parentVersion := container.GetConfigItem(templdir+"/config", "subutai.parent.version")

	if parent != "" && parent != t.name && !container.IsTemplate(parent) && !stringInList(parent, auxDepList) {
		// Append the template and parent name to dependency list
		auxDepList = append(auxDepList, parent, t.name)
		log.Info("Parent template required: " + parent + "@" + parentOwner + ":" + parentVersion)
		LxcImport(parent+"@"+parentOwner+":"+parentVersion, token, local, auxDepList...)
	}

	log.Info("Installing template " + t.name)
	template.Install(parent, t.name)
	// TODO following lines kept for back compatibility with old templates, should be deleted when all templates will be replaced.
	os.Rename(config.Agent.LxcPrefix+t.name+"/"+t.name+"-home", config.Agent.LxcPrefix+t.name+"/home")
	os.Rename(config.Agent.LxcPrefix+t.name+"/"+t.name+"-var", config.Agent.LxcPrefix+t.name+"/var")
	os.Rename(config.Agent.LxcPrefix+t.name+"/"+t.name+"-opt", config.Agent.LxcPrefix+t.name+"/opt")
	log.Check(log.FatalLevel, "Removing temp dir "+templdir, os.RemoveAll(templdir))

	//delete template archive
	fs.DeleteFilesWildcard(config.Agent.LxcPrefix + "tmpdir/" + t.file)

	if t.name == "management" {
		template.MngInit()
		return
	}

	container.SetContainerConf(t.name, [][]string{
		{"lxc.include", ""},
	})

	container.SetContainerConf(t.name, [][]string{
		{"lxc.rootfs", config.Agent.LxcPrefix + t.name + "/rootfs"},
		{"lxc.rootfs.mount", config.Agent.LxcPrefix + t.name + "/rootfs"},
		{"lxc.mount", config.Agent.LxcPrefix + t.name + "/fstab"},
		{"lxc.hook.pre-start", ""},
		{"lxc.include", config.Agent.AppPrefix + "share/lxc/config/ubuntu.common.conf"},
		{"lxc.include", config.Agent.AppPrefix + "share/lxc/config/ubuntu.userns.conf"},
		{"subutai.config.path", config.Agent.AppPrefix + "etc"},
		{"lxc.network.script.up", config.Agent.AppPrefix + "bin/create_ovs_interface"},
		{"lxc.mount.entry", config.Agent.LxcPrefix + t.name + "/home home none bind,rw 0 0"},
		{"lxc.mount.entry", config.Agent.LxcPrefix + t.name + "/opt opt none bind,rw 0 0"},
		{"lxc.mount.entry", config.Agent.LxcPrefix + t.name + "/var var none bind,rw 0 0"},
	})

	if t.id != "" {
		templateInfo, err := json.Marshal(&t)
		if err == nil {
			bolt, err := db.New()
			log.Check(log.WarnLevel, "Opening database", err)
			log.Check(log.WarnLevel, "Writing container data to database", bolt.TemplateAdd(t.id, map[string]string{"templateInfo": string(templateInfo)}))
			log.Check(log.WarnLevel, "Closing database", bolt.Close())
		}
	}

}

func getVersion(fileName string) string {

	return strings.Replace(strings.SplitAfter(fileName, "subutai-template_")[1], "_"+strings.ToLower(runtime.GOARCH)+".tar.gz", "", 1)
}

func verifySignature(t templ) {

	if len(t.id) != 0 && len(t.signature) == 0 {
		log.Error("Template is not signed")
	}

	for owner, signature := range t.signature {
		for _, key := range gpg.KurjunUserPK(owner) {
			if t.id == gpg.VerifySignature(key, signature) {
				log.Info("Template's owner signature verified")
				log.Debug("Signature belongs to " + owner)
				return
			}
			log.Debug("Signature does not match with template id")
		}
	}
	log.Error("Failed to verify signature")
}

// Verify if package is already on dependency list
func stringInList(s string, list []string) bool {
	for _, i := range list {
		if s == i {
			return true
		}
	}
	return false
}
