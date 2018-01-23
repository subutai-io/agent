package cli

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
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

// templateID retrieves the id of a template on global repository, id of the latest template version will be returned
func templateID(t *templ, kurjun *http.Client, token string) {
	var meta []metainfo

	url := config.CDN.Kurjun + "/template/info?name=" + t.name + "&token=" + token

	response, err := kurjun.Get(url)
	log.Check(log.ErrorLevel, "Retrieving id, get: "+url, err)
	defer utils.Close(response)

	if err == nil && response.StatusCode == 404 && t.name == "management" {
		log.Warn("Requested management version not found, getting latest available")
		response, err = kurjun.Get(config.CDN.Kurjun + "/template/info?name=" + t.name + "&version=" + config.Template.Branch + "&token=" + token)
		if err == nil {
			defer utils.Close(response)
		}
	}
	if log.Check(log.WarnLevel, "Getting kurjun response", err) || response.StatusCode != 200 {
		return
	}

	body, err := ioutil.ReadAll(response.Body)

	if err != nil || log.Check(log.WarnLevel, "Parsing response body", json.Unmarshal(body, &meta)) {
		return
	}

	if len(meta) == 0 {
		return
	}

	t.name = meta[0].Name
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

// checkLocal reads content of local templates folder to check if required archive is present there
func checkLocal(t *templ) (bool, string) {
	var response string
	files, _ := ioutil.ReadDir(config.Agent.LxcPrefix + "tmpdir")
	for _, f := range files {
		if strings.HasPrefix(f.Name(), t.name+"-subutai-template") {
			if len(t.id) == 0 {
				fmt.Print("Cannot verify local template. Trust anyway? (y/n)")
				_, err := fmt.Scanln(&response)
				log.Check(log.FatalLevel, "Reading input", err)
				if response == "y" {
					t.file = f.Name()
					return true, f.Name()
				}
				return false, ""
			}
			hash := md5sum(config.Agent.LxcPrefix + "tmpdir/" + f.Name())
			if t.id == hash || t.md5 == hash {
				return true, f.Name()
			}
		}
	}
	return false, ""
}

func downloadWithRetry(t templ, kurjun *http.Client, token string, retry int) bool {

	if len(t.id) == 0 {
		return false
	}

	for c := 0; c < retry; c++ {
		ok, err := download(t, kurjun, token)
		if err == nil {
			return ok
		} else {
			log.Check(log.WarnLevel, "Download interrupted, retrying", err)
		}
	}

	return false
}

// download gets template archive from global repository
func download(t templ, kurjun *http.Client, token string) (bool, error) {

	out, err := os.Create(config.Agent.LxcPrefix + "tmpdir/" + t.file)
	if err != nil {
		return false, err
	}
	defer out.Close()

	url := config.CDN.Kurjun + "/template/download?id=" + t.id + "&token=" + token

	if len(t.owner) > 0 {
		url = config.CDN.Kurjun + "/template/" + t.owner[0] + "/" + t.file + "?token=" + token
	}
	response, err := kurjun.Get(url)
	if err != nil {
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
		return false, err
	}

	hash := md5sum(config.Agent.LxcPrefix + "tmpdir/" + t.file)
	if t.id == hash || t.md5 == hash {
		return true, nil
	}

	return false, err
}

// idToName retrieves template name from global repository by passed id string
func idToName(id string, kurjun *http.Client, token string) string {
	bolt, err := db.New()
	log.Check(log.WarnLevel, "Opening database", err)
	if name := bolt.TemplateName(id); len(name) > 0 {
		log.Check(log.WarnLevel, "Closing database", bolt.Close())
		return name
	}
	log.Check(log.WarnLevel, "Closing database", bolt.Close())

	var meta []metainfo

	//Since only kurjun knows template's ID, we cannot define if we have template already installed in system by ID as we do it by name, so unreachable kurjun in this case is a deadend for us
	//To omit this issue we should add ID into template config and use this ID as a "primary key" to any request
	response, err := kurjun.Get(config.CDN.Kurjun + "/template/info?id=" + id + "&token=" + token)
	log.Check(log.ErrorLevel, "Getting kurjun response", err)
	defer utils.Close(response)

	body, err := ioutil.ReadAll(response.Body)

	if string(body) == "Not found" {
		log.Error("Template with id \"" + id + "\" not found")
	}
	if log.Check(log.WarnLevel, "Parsing response body", json.Unmarshal(body, &meta)) {
		var oldmeta metainfo
		log.Check(log.ErrorLevel, "Parsing response body from old Kurjun server", json.Unmarshal(body, &oldmeta))
		meta = append(meta, oldmeta)
	}

	if len(meta) > 0 {
		return meta[0].Name
	}
	return ""
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
// If Internet access is lost, or it is not possible to upload custom templates to the repository, the filesystem path `/mnt/lib/lxc/tmpdir/` could be used as local repository;
// the import sub command checks this directory if a requested published template or the global repository is not available.
//
// The import binding handles security checks to confirm the authenticity and integrity of templates. Besides using strict SSL connections for downloads,
// it verifies the fingerprint and its checksum for each template: an MD5 hash sum signed with author's GPG key. Import executes different integrity and authenticity checks of the template
// transparent to the user to protect system integrity from all possible risks related to template data transfers over the network.
//
// The template's version may be specified with the `-v` option. By default import retrieves the latest available template version from repository.
// The repository supports public, group private (shared), and private files. Import without specifying a security token can only access public templates.
//
// `subutai import management` is a special operation which differs from the import of other templates. Besides the usual template deployment operations,
// "import management" demotes the template, starts its container, transforms the host network, and forwards a few host ports, etc.
func LxcImport(name, token string, auxDepList ...string) {
	var kurjun *http.Client

	if container.ContainerOrTemplateExists(name) && name == "management" && len(token) > 1 {
		gpg.ExchageAndEncrypt("management", token)
		return
	}

	if id := strings.Split(name, "id:"); len(id) > 1 {
		kurjun, _ = config.CheckKurjun()
		if kurjun != nil {
			name = idToName(id[1], kurjun, token)
		}
	}

	var t templ

	t.name = name
	if line := strings.Split(t.name, "/"); len(line) > 1 {
		t.name = line[1]
		t.owner = append(t.owner, line[0])
	}

	log.Info("Importing " + name)

	var lock lockfile.Lockfile
	var err error
	for lock, err = lockSubutai(t.name + ".import"); err != nil; lock, err = lockSubutai(t.name + ".import") {
		time.Sleep(time.Second * 1)
	}
	defer lock.Unlock()

	if container.ContainerOrTemplateExists(t.name) {
		log.Info(t.name + " instance exists")
		return
	}

	if kurjun == nil {
		kurjun, _ = config.CheckKurjun()
	}
	if kurjun != nil {
		templateID(&t, kurjun, token)
		log.Info("Version: " + t.version)
	} else {
		log.Info("Trying to import from local storage")
	}

	if len(t.id) != 0 && len(t.signature) == 0 {
		log.Error("Template is not signed")
	}

	log.Check(log.ErrorLevel, "Verifying template signature", verifySignature(t.id, t.signature))

	archiveExists, archiveName := checkLocal(&t)

	//check if template update is needed
	updateRequired := false

	if archiveExists {

		archiveVersion := strings.TrimRight(strings.TrimLeft(strings.ToLower(archiveName),
			strings.ToLower(name)+"-subutai-template_"), "_"+strings.ToLower(runtime.GOARCH)+".tar.gz")

		updateRequired = !strings.EqualFold(t.version, archiveVersion)

		if updateRequired {

			log.Debug("Removing outdated template " + name + " of version " + archiveVersion)

			container.DestroyTemplate(name)
		} else {

			log.Debug("Template is of latest version")
		}

	} else {
		log.Debug("Archive is missing in local cache")
	}

	if !archiveExists || updateRequired {
		if updateRequired {
			log.Info("Updating " + t.name)
		} else {
			log.Info("Downloading " + t.name)
		}

		downloaded := false

		if len(t.owner) == 0 {
			for _, owner := range owners {
				if t.owner = []string{owner}; len(owner) == 0 {
					t.owner = []string{}
				}
				if downloadWithRetry(t, kurjun, token, 5) {
					downloaded = true
					break
				}
			}
		}

		if !downloaded && !downloadWithRetry(t, kurjun, token, 5) {

			log.Error("Failed to download or verify template " + t.name)
		} else {

			log.Info("File integrity verified")
		}
	}

	log.Info("Unpacking template " + t.name)
	log.Debug(config.Agent.LxcPrefix + "tmpdir/" + t.file + " to " + t.name)
	tgz := extractor.NewTgz()
	templdir := config.Agent.LxcPrefix + "tmpdir/" + t.name
	log.Check(log.FatalLevel, "Extracting tgz", tgz.Extract(config.Agent.LxcPrefix+"tmpdir/"+t.file, templdir))
	parent := container.GetConfigItem(templdir+"/config", "subutai.parent")

	if parent != "" && parent != t.name && !container.IsTemplate(parent) && !stringInList(parent, auxDepList) {
		// Append the template and parent name to dependency list
		auxDepList = append(auxDepList, parent, t.name)
		log.Info("Parent template required: " + parent)
		LxcImport(parent, token, auxDepList...)
	}

	log.Info("Installing template " + t.name)
	template.Install(parent, t.name)
	// TODO following lines kept for back compatibility with old templates, should be deleted when all templates will be replaced.
	os.Rename(config.Agent.LxcPrefix+t.name+"/"+t.name+"-home", config.Agent.LxcPrefix+t.name+"/home")
	os.Rename(config.Agent.LxcPrefix+t.name+"/"+t.name+"-var", config.Agent.LxcPrefix+t.name+"/var")
	os.Rename(config.Agent.LxcPrefix+t.name+"/"+t.name+"-opt", config.Agent.LxcPrefix+t.name+"/opt")
	log.Check(log.FatalLevel, "Removing temp dir "+templdir, os.RemoveAll(templdir))

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

	bolt, err := db.New()
	log.Check(log.WarnLevel, "Opening database", err)
	log.Check(log.WarnLevel, "Writing container data to database", bolt.TemplateAdd(t.name, t.id))
	log.Check(log.WarnLevel, "Closing database", bolt.Close())
}

func verifySignature(id string, list map[string]string) error {
	if len(list) == 0 {
		return nil
	}
	for owner, signature := range list {
		for _, key := range gpg.KurjunUserPK(owner) {
			if id == gpg.VerifySignature(key, signature) {
				log.Info("Template's owner signature verified")
				log.Debug("Signature belongs to " + owner)
				return nil
			}
			log.Debug("Signature does not match with template id")
		}
	}
	return fmt.Errorf("failed to verify signature")
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
