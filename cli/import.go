package cli

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"code.cloudfoundry.org/archiver/extractor"
	"github.com/nightlyone/lockfile"
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
	"path"
	"github.com/subutai-io/agent/lib/common"
	"github.com/subutai-io/agent/lib/exec"
)

type Template struct {
	Id      string `json:"id"`
	Name    string `json:"name"`
	Owner   string `json:"owner"`
	Version string `json:"version"`
	MD5     string `json:"md5"`
	Parent  string `json:"parent"`
	Size    int64  `json:"size"`
}

func init() {
	if _, err := os.Stat(config.Agent.CacheDir); os.IsNotExist(err) {
		os.MkdirAll(config.Agent.CacheDir, 0755)
	}
}

// getTemplateInfoById retrieves template name from global repository by passed id string
func getTemplateInfoById(t *Template, id string) {
	url := config.CdnUrl + "/template?id=" + id

	kurjun := utils.GetClient(config.CDN.Allowinsecure, 15)
	response, err := kurjun.Get(url)
	log.Check(log.ErrorLevel, "Retrieving template info, get: "+url, err)
	defer utils.Close(response)

	if response.StatusCode == 404 {
		log.Error("Template " + t.Name + " not found")
	}
	if response.StatusCode != 200 {
		log.Error("Failed to get template info:  " + response.Status)
	}

	body, err := ioutil.ReadAll(response.Body)
	log.Check(log.ErrorLevel, "Reading template info, get: "+url, err)

	var templ Template
	if log.Check(log.WarnLevel, "Parsing response body", json.Unmarshal(body, &templ)) {
		log.Error("Failed to parse template info")
	}

	t.Name = templ.Name
	t.Owner = templ.Owner
	t.Version = templ.Version
	t.Id = templ.Id
	t.MD5 = templ.MD5
	t.Parent = templ.Parent
	t.Size = templ.Size

	log.Debug("Template identified as " + t.Name + "@" + t.Owner + ":" + t.Version)
}

//TODO urlEncode the kurjun URL
func getTemplateInfoByName(t *Template, name string, owner string, version string) {
	url := config.CdnUrl + "/template?name=" + name

	if owner != "" {
		url += "&owner=" + owner
	}

	if version == "" {
		url += "&version=latest"
	} else {
		url += "&version=" + version
	}

	kurjun := utils.GetClient(config.CDN.Allowinsecure, 15)
	response, err := kurjun.Get(url)
	log.Check(log.ErrorLevel, "Retrieving template info, get: "+url, err)
	defer utils.Close(response)

	if response.StatusCode == 404 {
		log.Error("Template " + t.Name + " not found")
	}
	if response.StatusCode != 200 {
		log.Error("Failed to get template info:  " + response.Status)
	}

	body, err := ioutil.ReadAll(response.Body)
	log.Check(log.ErrorLevel, "Reading template info, get: "+url, err)

	var templ Template
	if log.Check(log.WarnLevel, "Parsing response body", json.Unmarshal(body, &templ)) {
		log.Error("Failed to parse template info")
	}

	t.Name = templ.Name
	t.Owner = templ.Owner
	t.Version = templ.Version
	t.Id = templ.Id
	t.MD5 = templ.MD5
	t.Parent = templ.Parent
	t.Size = templ.Size

	log.Debug("Template identified as " + t.Name + "@" + t.Owner + ":" + t.Version)
}

func getTemplateInfoFromCacheById(templateId string) (Template, bool) {
	meta, err := db.INSTANCE.TemplateByName(templateId)

	if !log.Check(log.WarnLevel, "Getting template metadata from db", err) {
		templateInfo, found := meta["templateInfo"]
		if found {
			log.Debug("Found cached template info:\n" + templateInfo)
			var t Template
			err := json.Unmarshal([]byte(templateInfo), &t)
			if err == nil {
				return t, true
			}
		}
	}

	return Template{}, false
}

func getTemplateInfoFromCacheByName(name, owner, version string) (Template, bool) {

	var key, value string
	if name != "" && owner != "" && version != "" {
		key = "nameAndOwnerAndVersion"
		value = strings.Join([]string{name, owner, version}, ":")
	} else if name != "" && owner != "" {
		key = "nameAndOwner"
		value = strings.Join([]string{name, owner}, ":")
	} else {
		key = "name"
		value = name
	}

	templates, err := db.INSTANCE.TemplateByKey(key, value)
	if !log.Check(log.WarnLevel, "Getting template metadata from db", err) &&
		len(templates) > 0 {
		//first found template is returned if several meet the specified criteria
		return getTemplateInfoFromCacheById(templates[0])
	}

	return Template{}, false
}

func getTemplateInfo(template string) Template {

	var t Template

	if id := strings.Split(template, "id:"); len(id) > 1 {
		templateId := id[1]

		if t, found := getTemplateInfoFromCacheById(templateId); found {
			return t
		}

		getTemplateInfoById(&t, templateId)

	} else {

		// full template reference is template@owner:version e.g. master@subutai:4.0.0
		// if owner is missing then we use verified only, if version is missing we use latest version

		if templateNameNOwnerNVersionRx.MatchString(template) {
			groups := utils.MatchRegexGroups(templateNameNOwnerNVersionRx, template)

			if t, found := getTemplateInfoFromCacheByName(groups["name"], groups["owner"], groups["version"]); found {
				return t
			}

			getTemplateInfoByName(&t, groups["name"], groups["owner"], groups["version"])
		} else if templateNameNOwnerRx.MatchString(template) {
			groups := utils.MatchRegexGroups(templateNameNOwnerRx, template)

			if t, found := getTemplateInfoFromCacheByName(groups["name"], groups["owner"], ""); found {
				return t
			}

			getTemplateInfoByName(&t, groups["name"], groups["owner"], "")
		} else if templateNameRx.MatchString(template) {
			groups := utils.MatchRegexGroups(templateNameRx, template)

			if t, found := getTemplateInfoFromCacheByName(groups["name"], "", ""); found {
				return t
			}

			getTemplateInfoByName(&t, groups["name"], "", "")
		} else {
			log.Error("Invalid template name " + template)
		}

	}

	return t
}

// md5sum returns MD5 hash sum of specified file
func md5sum(filePath string) string {
	hash, err := fs.Md5Sum(filePath)
	log.Check(log.WarnLevel, "Getting md5sum of "+filePath, err)
	return hash
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
// If Internet access is lost, or it is not possible to upload custom templates to the repository, the filesystem path config.Agent.CacheDir could be used as local repository;
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
// "subutai import management -t {secret}" is executed by Console to register the container with itself,
// Console passes special secret token in place of CDN token using -t switch in this operation
func LxcImport(name, token string, local bool, auxDepList ...string) {
	var err error

	if !fs.IsMountPoint(config.Agent.LxcPrefix) {
		log.Fatal("Lxc directory " + config.Agent.LxcPrefix + " not mounted")
	}

	if container.LxcInstanceExists(name) && name == "management" && len(token) > 1 {
		gpg.ExchageAndEncrypt("management", token)
		return
	}

	var t Template
	var templateRef string
	var localArchive string

	if !local {
		t = getTemplateInfo(name)
		templateRef = strings.Join([]string{t.Name, t.Owner, t.Version}, ":")
		localArchive = path.Join(config.Agent.CacheDir, t.Id)
	} else {
		//for local import we currently use only name and ignore owner and version!
		nameParts := common.Splitter(name, ":@")
		t.Name = nameParts[0]
		templateRef = t.Name

		wildcardTemplateName := path.Join(config.Agent.CacheDir, strings.ToLower(t.Name)+
			"-subutai-template_*_"+ strings.ToLower(runtime.GOARCH)+ ".tar.gz")

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

			localArchive = latestVersionFile

		} else {
			log.Error("Template " + t.Name + " not found in local cache")
		}
	}

	log.Info("Importing " + t.Name)

	var lock lockfile.Lockfile
	for lock, err = lockSubutai(templateRef + ".import"); err != nil; lock, err = lockSubutai(templateRef + ".import") {
		time.Sleep(time.Second * 1)
	}
	defer lock.Unlock()

	//for local import this check currently does not work
	if container.LxcInstanceExists(templateRef) {
		if t.Name == "management" && !container.IsContainer("management") {
			template.MngInit(templateRef)
			return
		}
		//!important used by Console
		log.Info(t.Name + " instance exists")
		return
	}

	var archiveExists = fs.FileExists(localArchive)

	if archiveExists {

		log.Debug("Template archive is present in local cache")

		if !local {
			md5 := md5sum(localArchive)
			if t.MD5 == md5 {

				log.Debug("File integrity is verified")
			} else {

				log.Warn("File integrity verification failed")

				//make agent re-download verified template from CDN
				archiveExists = false
			}
		} else {
			log.Warn("Skipping file integrity verification since -local flag was passed")
		}

	} else {

		log.Debug("Template archive is missing in local cache")
	}

	if !archiveExists {
		download(t)
	}

	//!important used by Console
	log.Info("Unpacking template " + t.Name)
	log.Debug(localArchive + " to " + templateRef)
	tgz := extractor.NewTgz()
	templdir := path.Join(config.Agent.CacheDir, templateRef)
	log.Check(log.FatalLevel, "Extracting tgz", tgz.Extract(localArchive, templdir))

	templateName := container.GetConfigItem(templdir+"/config", "subutai.template")
	templateOwner := container.GetConfigItem(templdir+"/config", "subutai.template.owner")
	templateVersion := container.GetConfigItem(templdir+"/config", "subutai.template.version")

	if local {
		//rename template directory to follow full reference convention
		templateRef = strings.Join([]string{templateName, templateOwner, templateVersion}, ":")
		os.Rename(templdir, path.Join(config.Agent.CacheDir, templateRef))
		templdir = path.Join(config.Agent.CacheDir, templateRef)
	}

	parent := container.GetConfigItem(templdir+"/config", "subutai.parent")
	parentOwner := container.GetConfigItem(templdir+"/config", "subutai.parent.owner")
	parentVersion := container.GetConfigItem(templdir+"/config", "subutai.parent.version")

	parentRef := strings.Join([]string{parent, parentOwner, parentVersion}, ":")
	if parentRef != templateRef && !container.IsTemplate(parentRef) && !stringInList(parentRef, auxDepList) {
		// Append the template and parent name to dependency list
		auxDepList = append(auxDepList, parentRef, templateRef)
		log.Info("Parent template required: " + parentRef)
		LxcImport(parentRef, token, local, auxDepList...)
	}

	//!important used by Console
	log.Info("Installing template " + t.Name)

	//delete dataset if already exists
	if fs.DatasetExists(templateRef) {
		fs.RemoveDataset(templateRef, true)
	}

	template.Install(templateRef)

	log.Check(log.FatalLevel, "Removing temp dir "+templdir, os.RemoveAll(templdir))

	//delete template archive
	if !local {
		log.Check(log.WarnLevel, "Removing file: "+localArchive, os.Remove(localArchive))
	}

	if t.Name == "management" {
		template.MngInit(templateRef)
		return
	}

	log.Check(log.ErrorLevel, "Setting lxc config", updateContainerConfig(templateRef))

	if !local {
		cacheTemplateInfo(t)
	} else {
		//cache local template info
		size, _ := fs.FileSize(localArchive)
		templateInfo := Template{
			Id:      strings.Join([]string{templateName, templateOwner, templateVersion}, ":"),
			Owner:   templateOwner,
			Version: templateVersion,
			Name:    templateName,
			Size:    size,
			Parent:  parentRef,
			MD5:     md5sum(localArchive),
		}

		cacheTemplateInfo(templateInfo)

	}

}
func download(template Template) {

	log.Debug("Checking template availability in CDN network...")

	err := exec.Exec("timeout", "30", "ipfs", "dht", "findprovs", "-n1", template.Id)

	if err != nil {
		log.Fatal("Template not found in CDN network")
	}

	//!important used by Console
	log.Info("Downloading " + template.Name)

	templatePath := path.Join(config.Agent.CacheDir, template.Id)

	//download template
	_, err = exec.ExecuteOutput("ipfs", "get", template.Id, "-o", templatePath)
	log.Check(log.FatalLevel, "Downloading template", err)

	//verify its md5 sum
	if template.MD5 != md5sum(templatePath) {
		log.Fatal("File integrity verification failed")
	}

	//pin template
	exec.Exec("ipfs", "pin", "add", template.Id)
}

func updateContainerConfig(templateName string) error {

	cfg := container.LxcConfig{}
	err := cfg.Load(path.Join(config.Agent.LxcPrefix, templateName, "config"))
	if err != nil {
		return err
	}

	cfg.SetParams([][]string{
		{"lxc.rootfs", path.Join(config.Agent.LxcPrefix, templateName, "rootfs")},
		{"lxc.mount.entry", path.Join(config.Agent.LxcPrefix, templateName, "home") + " home none bind,rw 0 0"},
		{"lxc.mount.entry", path.Join(config.Agent.LxcPrefix, templateName, "opt") + " opt none bind,rw 0 0"},
		{"lxc.mount.entry", path.Join(config.Agent.LxcPrefix, templateName, "var") + " var none bind,rw 0 0"},
	})

	return cfg.Save()
}

func cacheTemplateInfo(t Template) {
	templateInfo, err := json.Marshal(&t)
	if err == nil {
		log.Check(log.WarnLevel, "Writing template data to database",
			db.INSTANCE.TemplateAdd(t.Id,
				map[string]string{"templateInfo": string(templateInfo),
					"name": t.Name,
					"nameAndOwner": strings.Join([]string{t.Name, t.Owner}, ":"),
					"nameAndOwnerAndVersion": strings.Join([]string{t.Name, t.Owner, t.Version}, ":"),
				}))
	}
}

func getVersion(fileName string) string {

	return strings.Replace(strings.SplitAfter(fileName, "subutai-template_")[1], "_"+strings.ToLower(runtime.GOARCH)+".tar.gz", "", 1)
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
