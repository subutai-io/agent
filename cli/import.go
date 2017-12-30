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
)

var (
	lock   lockfile.Lockfile
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

// templateID retrieves the id of a template on global repository with specified version.
// If certain version is not set, then latest id will be returned
func templateID(t *templ, kurjun *http.Client, token string) {
	var meta []metainfo

	url := config.CDN.Kurjun + "/template/info?name=" + t.name + "&token=" + token
	if t.name == "management" && len(t.version) != 0 {
		url = url + "&version=" + t.version
	}

	response, err := kurjun.Get(url)
	defer response.Body.Close()
	log.Check(log.ErrorLevel, "Retrieving id, get: "+url, err)

	if err == nil && response.StatusCode == 404 && t.name == "management" {
		log.Warn("Requested management version not found, getting latest available")
		response, err = kurjun.Get(config.CDN.Kurjun + "/template/info?name=" + t.name + "&version=" + config.Template.Branch + "&token=" + token)
		defer response.Body.Close()
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
	defer file.Close()
	if err != nil {
		return ""
	}

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return ""
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
}

// checkLocal reads content of local templates folder to check if required archive is present there
func checkLocal(t *templ) bool {
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
					return true
				}
				return false
			}
			hash := md5sum(config.Agent.LxcPrefix + "tmpdir/" + f.Name())
			if t.id == hash || t.md5 == hash {
				return true
			}
		}
	}
	return false
}

// download gets template archive from global repository
func download(t templ, kurjun *http.Client, token string, torrent bool) bool {
	if len(t.id) == 0 {
		return false
	}
	out, err := os.Create(config.Agent.LxcPrefix + "tmpdir/" + t.file)
	defer out.Close()
	log.Check(log.FatalLevel, "Creating file "+t.file, err)

	url := config.CDN.Kurjun + "/template/download?id=" + t.id + "&token=" + token

	if len(t.owner) > 0 {
		url = config.CDN.Kurjun + "/template/" + t.owner[0] + "/" + t.file + "?token=" + token
	}
	response, err := kurjun.Get(url)
	defer response.Body.Close()
	log.Check(log.FatalLevel, "Getting "+url, err)

	bar := pb.New(int(response.ContentLength)).SetUnits(pb.U_BYTES)
	if response.ContentLength <= 0 {
		bar.NotPrint = true
	}
	bar.Start()
	rd := bar.NewProxyReader(response.Body)
	_, err = io.Copy(out, rd)
	for c := 0; err != nil && c < 5; _, err = io.Copy(out, rd) {
		log.Info("Download interrupted, retrying")
		time.Sleep(3 * time.Second)
		c++

		//Repeating GET request to CDN, while need to continue interrupted download
		out, err = os.Create(config.Agent.LxcPrefix + "tmpdir/" + t.file)
		defer out.Close()
		log.Check(log.FatalLevel, "Creating file "+t.file, err)
		response, err = kurjun.Get(url)
		defer response.Body.Close()
		log.Check(log.FatalLevel, "Getting "+url, err)
		bar = pb.New(int(response.ContentLength)).SetUnits(pb.U_BYTES)
		bar.Start()
		rd = bar.NewProxyReader(response.Body)
	}
	log.Check(log.FatalLevel, "Writing response body to file", err)
	bar.Finish()

	hash := md5sum(config.Agent.LxcPrefix + "tmpdir/" + t.file)
	if t.id == hash || t.md5 == hash {
		return true
	}
	return false
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
	defer response.Body.Close()
	log.Check(log.ErrorLevel, "Getting kurjun response", err)

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
func lockSubutai(file string) bool {
	lock, err := lockfile.New("/var/run/lock/subutai." + file)
	if log.Check(log.DebugLevel, "Init lock "+file, err) {
		return false
	}

	err = lock.TryLock()
	if log.Check(log.DebugLevel, "Locking file "+file, err) {
		if p, err := lock.GetOwner(); err == nil {
			cmd, err := ioutil.ReadFile(fmt.Sprintf("/proc/%v/cmdline", p.Pid))
			if err != nil || !(strings.Contains(string(cmd), "subutai") && strings.Contains(string(cmd), "import")) {
				log.Check(log.DebugLevel, "Removing broken lockfile /var/run/lock/subutai."+file, os.Remove("/var/run/lock/subutai."+file))
			}
		}
		return false
	}

	return true
}

// unlockSubutai removes lock file
func unlockSubutai() {
	lock.Unlock()
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
func LxcImport(name, version, token string, torrent bool, auxDepList ...string) {
	var kurjun *http.Client

	if container.IsContainer(name) && name == "management" && len(token) > 1 {
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
	for !lockSubutai(t.name + ".import") {
		time.Sleep(time.Second * 1)
	}
	defer unlockSubutai()

	if container.IsContainer(t.name) {
		log.Info(t.name + " instance exist")
		return
	}

	// t.version = config.Template.Version
	// t.branch = config.Template.Branch
	t.version = version

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

	if !checkLocal(&t) {
		log.Info("Downloading " + t.name)
		downloaded := false
		if len(t.owner) == 0 {
			for _, owner := range owners {
				if t.owner = []string{owner}; len(owner) == 0 {
					t.owner = []string{}
				}
				if download(t, kurjun, token, torrent) {
					downloaded = true
					break
				}
			}
		}
		if !downloaded && !download(t, kurjun, token, torrent) {
			log.Error("Failed to download or verify template " + t.name)
		} else {
			log.Info("File integrity verified")
		}
	}

	log.Info("Unpacking template " + t.name)
	log.Debug(config.Agent.LxcPrefix + "tmpdir/ " + t.file + " to " + t.name)
	tgz := extractor.NewTgz()
	templdir := config.Agent.LxcPrefix + "tmpdir/" + t.name
	log.Check(log.FatalLevel, "Extracting tgz", tgz.Extract(config.Agent.LxcPrefix+"tmpdir/"+t.file, templdir))
	parent := container.GetConfigItem(templdir+"/config", "subutai.parent")

	if parent != "" && parent != t.name && !container.IsTemplate(parent) && !stringInList(parent, auxDepList) {
		// Append the template and parent name to dependency list
		auxDepList = append(auxDepList, parent, t.name)
		log.Info("Parent template required: " + parent)
		LxcImport(parent, "", token, torrent, auxDepList...)
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
	return fmt.Errorf("Failed to verify signature")
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
