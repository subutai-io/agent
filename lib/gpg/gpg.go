package gpg

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/clearsign"

	"github.com/subutai-io/base/agent/agent/utils"
	"github.com/subutai-io/base/agent/config"
	"github.com/subutai-io/base/agent/lib/container"
	"github.com/subutai-io/base/agent/log"
)

//ImportPk imports Public Key "gpg2 --import pubkey.key".
func ImportPk(k []byte) string {
	tmpfile, err := ioutil.TempFile("", "subutai-epub")
	if !log.Check(log.WarnLevel, "Creating Public key file", err) {

		_, err = tmpfile.Write(k)
		log.Check(log.WarnLevel, "Writing Management server Public key to "+tmpfile.Name(), err)
		log.Check(log.WarnLevel, "Closing "+tmpfile.Name(), tmpfile.Close())

		out, err := exec.Command("gpg", "--import", tmpfile.Name()).CombinedOutput()
		log.Check(log.WarnLevel, "Importing MH Public key from "+tmpfile.Name(), err)
		log.Check(log.WarnLevel, "Removing temp file", os.Remove(tmpfile.Name()))
		return string(out)
	}
	return err.Error()
}

// GetContainerPk returns GPG Public Key for container.
func GetContainerPk(name string) string {
	lxcPath := config.Agent.LxcPrefix + name + "/public.pub"
	stdout, err := exec.Command("/bin/bash", "-c", "gpg --no-default-keyring --keyring "+lxcPath+" --export -a "+name+"@subutai.io").Output()
	log.Check(log.WarnLevel, "Getting Container public key", err)
	return string(stdout)
}

// GetPk returns GPG Public Key from the Resource Host.
func GetPk(name string) string {
	stdout, err := exec.Command("gpg", "--export", "-a", name).Output()
	log.Check(log.WarnLevel, "Getting public key", err)
	if len(stdout) == 0 {
		log.Warn("GPG key for RH not found. Creating new.")
		GenerateKey(name)
	}
	return string(stdout)
}

// DecryptWrapper decrypts GPG message.
func DecryptWrapper(args ...string) string {
	gpg := "gpg --passphrase " + config.Agent.GpgPassword + " --no-tty"
	if len(args) == 3 {
		gpg = gpg + " --no-default-keyring --keyring " + args[2] + " --secret-keyring " + args[1]
	}
	command := exec.Command("/bin/bash", "-c", gpg)
	stdin, err := command.StdinPipe()
	if err == nil {
		_, err = stdin.Write([]byte(args[0]))
		log.Check(log.DebugLevel, "Writing to stdin of gpg", err)
		log.Check(log.DebugLevel, "Closing stdin of gpg", stdin.Close())
	}

	output, err := command.Output()
	log.Check(log.WarnLevel, "Executing command "+gpg, err)

	return string(output)
}

// EncryptWrapper encrypts GPG message.
func EncryptWrapper(user, recipient string, message []byte, args ...string) string {
	gpg := "gpg --batch --passphrase " + config.Agent.GpgPassword + " --trust-model always --armor -u " + user + " -r " + recipient + " --sign --encrypt --no-tty"
	if len(args) >= 2 {
		gpg = gpg + " --no-default-keyring --keyring " + args[0] + " --secret-keyring " + args[1]
	}
	command := exec.Command("/bin/bash", "-c", gpg)
	stdin, err := command.StdinPipe()
	if err == nil {
		_, err = stdin.Write(message)
		log.Check(log.DebugLevel, "Writing to stdin of gpg", err)
		log.Check(log.DebugLevel, "Closing stdin of gpg", stdin.Close())
	}

	output, err := command.Output()
	if log.Check(log.WarnLevel, "Encrypting message", err) {
		return ""
	}

	return string(output)
}

// GenerateKey generates GPG-key for Subutai Agent.
// This key used for encrypting messages for Subutai Agent.
func GenerateKey(name string) {
	path := config.Agent.LxcPrefix + name
	email := name + "@subutai.io"
	pass := config.Agent.GpgPassword
	if !container.IsContainer(name) {
		err := os.MkdirAll("/root/.gnupg/", 0700)
		log.Check(log.DebugLevel, "Creating /root/.gnupg/", err)
		path = "/root/.gnupg"
		email = name
		pass = config.Agent.GpgPassword
	}
	// err := ioutil.WriteFile(config.Agent.LxcPrefix+c+"/defaults", ident, 0644)
	conf, err := os.Create(path + "/defaults")
	if log.Check(log.FatalLevel, "Writing default key ident", err) {
		return
	}
	_, err = conf.WriteString("%echo Generating default keys\n" +
		"Key-Type: RSA\n" +
		"Key-Length: 2048\n" +
		"Name-Real: " + name + "\n" +
		"Name-Comment: " + name + " GPG key\n" +
		"Name-Email: " + email + "\n" +
		"Expire-Date: 0\n" +
		"Passphrase: " + pass + "\n" +
		"%pubring " + path + "/public.pub\n" +
		"%secring " + path + "/secret.sec\n" +
		"%commit\n" +
		"%echo Done\n")
	log.Check(log.DebugLevel, "Writing defaults for gpg", err)
	log.Check(log.DebugLevel, "Closing defaults for gpg", conf.Close())

	log.Check(log.FatalLevel, "Generating key", exec.Command("gpg", "--batch", "--gen-key", path+"/defaults").Run())
	if !container.IsContainer(name) {
		log.Check(log.FatalLevel, "Importing secret key", exec.Command("gpg", "--allow-secret-key-import", "--import", "/root/.gnupg/secret.sec").Run())
		log.Check(log.FatalLevel, "Importing public key", exec.Command("gpg", "--import", "/root/.gnupg/public.pub").Run())
	}
}

// GetFingerprint returns fingerprint of the Subutai container.
func GetFingerprint(email string) string {
	var out []byte
	var err error
	if email == config.Agent.GpgUser {
		out, err = exec.Command("gpg", "--fingerprint", email).Output()
		log.Check(log.DebugLevel, "Getting fingerprint by "+email, err)
	} else {
		out, err = exec.Command("gpg", "--fingerprint", "--keyring", config.Agent.LxcPrefix+email+"/public.pub", email).Output()
		log.Check(log.DebugLevel, "Getting fingerprint by "+email, err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "fingerprint") {
			fp := strings.Split(scanner.Text(), "=")
			if len(fp) > 1 {
				return strings.Replace(fp[1], " ", "", -1)
			}
		}
	}
	return ""
}

func getMngKey(c string) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get("https://" + config.Management.Host + ":" + config.Management.Port + config.Management.RestPublicKey)
	log.Check(log.FatalLevel, "Getting Management public key", err)

	defer resp.Body.Close()
	if body, err := ioutil.ReadAll(resp.Body); err == nil {
		err = ioutil.WriteFile(config.Agent.LxcPrefix+c+"/mgn.key", body, 0644)
		log.Check(log.FatalLevel, "Writing Management public key", err)
	}
}

func parseKeyID(s string) string {
	var id string

	line := strings.Split(s, "\n")
	if len(line) > 2 {
		cell := strings.Split(line[1], " ")
		if len(cell) > 3 {
			key := strings.Split(cell[3], "/")
			if len(key) > 1 {
				id = key[1]
			}
		}
	}
	if len(id) == 0 {
		log.Fatal("Key id parsing error")
	}
	return id
}

func writeData(c, t, n, m string) {
	log.Check(log.DebugLevel, "Removing "+config.Agent.LxcPrefix+c+"/stdin.txt.asc", os.Remove(config.Agent.LxcPrefix+c+"/stdin.txt.asc"))
	log.Check(log.DebugLevel, "Removing "+config.Agent.LxcPrefix+c+"/stdin.txt", os.Remove(config.Agent.LxcPrefix+c+"/stdin.txt"))

	token := []byte(t + "\n" + GetFingerprint(c) + "\n" + n + m)
	err := ioutil.WriteFile(config.Agent.LxcPrefix+c+"/stdin.txt", token, 0644)
	log.Check(log.FatalLevel, "Writing Management public key", err)
}

func sendData(c string) {
	asc, err := os.Open(config.Agent.LxcPrefix + c + "/stdin.txt.asc")
	log.Check(log.FatalLevel, "Reading encrypted stdin.txt.asc", err)
	defer asc.Close()

	client := utils.TLSConfig()
	resp, err := client.Post("https://"+config.Management.Host+":8444/rest/v1/registration/verify/container-token", "text/plain", asc)
	log.Check(log.DebugLevel, "Removing "+config.Agent.LxcPrefix+c+"/stdin.txt.asc", os.Remove(config.Agent.LxcPrefix+c+"/stdin.txt.asc"))
	log.Check(log.DebugLevel, "Removing "+config.Agent.LxcPrefix+c+"/stdin.txt", os.Remove(config.Agent.LxcPrefix+c+"/stdin.txt"))
	log.Check(log.FatalLevel, "Sending registration request to management", err)

	if resp.StatusCode != 200 && resp.StatusCode != 202 {
		log.Error("Failed to exchange GPG Public Keys. StatusCode: " + resp.Status)
	}

}

// ExchageAndEncrypt installing the Management server GPG public key to the container keyring.
// Sending container's GPG public key to the Management server. It require encrypting and singing message
// received from the Management server.
func ExchageAndEncrypt(c, t string) {
	var impout, expout, imperr, experr bytes.Buffer

	getMngKey(c)

	impkey := exec.Command("gpg", "-v", "--no-default-keyring", "--keyring", config.Agent.LxcPrefix+c+"/public.pub", "--import", config.Agent.LxcPrefix+c+"/mgn.key")
	impkey.Stdout = &impout
	impkey.Stderr = &imperr
	err := impkey.Run()
	log.Check(log.FatalLevel, "Importing Management public key to keyring", err)

	id := parseKeyID(imperr.String())
	expkey := exec.Command("gpg", "--no-default-keyring", "--keyring", config.Agent.LxcPrefix+c+"/public.pub", "--export", "--armor", c+"@subutai.io")
	expkey.Stdout = &expout
	expkey.Stderr = &experr
	err = expkey.Run()
	log.Check(log.FatalLevel, "Exporting armomred key", err)

	writeData(c, t, expout.String(), experr.String())

	err = exec.Command("gpg", "--no-default-keyring", "--keyring", config.Agent.LxcPrefix+c+"/public.pub", "--trust-model", "always", "--armor", "-r", id, "--encrypt", config.Agent.LxcPrefix+c+"/stdin.txt").Run()
	log.Check(log.FatalLevel, "Encrypting stdin.txt", err)

	sendData(c)
}

// ValidatePem checks if OpenSSL x509 certificate valid.
func ValidatePem(cert string) bool {
	out, err := exec.Command("openssl", "x509", "-in", cert, "-text", "-noout").Output()
	log.Check(log.DebugLevel, "Validating OpenSSL x509 certificate", err)
	return strings.Contains(string(out), "Public Key")
}

// ParsePem return parsed OpenSSL x509 certificate.
func ParsePem(cert string) (crt, key []byte) {
	var err error
	if key, err = exec.Command("openssl", "pkey", "-in", cert).Output(); err == nil {
		f, err := ioutil.ReadFile(cert)
		if !log.Check(log.DebugLevel, "Cannot read file "+cert, err) {
			crt = bytes.Replace(f, key, []byte(""), -1)
		}
	}
	return crt, key
}

// KurjunUserPK gets user's public GPG-key from Kurjun.
func KurjunUserPK(owner string) string {
	kurjun, err := config.CheckKurjun()
	log.Check(log.DebugLevel, "Checking Kurjun", err)

	response, err := kurjun.Get(config.CDN.Kurjun + "/auth/key?user=" + owner)
	log.Check(log.FatalLevel, "Getting owner public key", err)
	defer response.Body.Close()

	key, err := ioutil.ReadAll(response.Body)
	log.Check(log.FatalLevel, "Reading key body", err)
	return string(key)
}

// VerifySignature check if signature retrieved from Kurjun is valid.
func VerifySignature(key, signature string) string {
	entity, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(key))
	log.Check(log.WarnLevel, "Reading user public key", err)

	if block, _ := clearsign.Decode([]byte(signature)); block != nil {
		_, err = openpgp.CheckDetachedSignature(entity, bytes.NewBuffer(block.Bytes), block.ArmoredSignature.Body)
		if log.Check(log.ErrorLevel, "Checking signature", err) {
			return ""
		}
		return string(block.Bytes)
	}
	return ""
}
