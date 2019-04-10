package cli

import (
	"strings"
	"github.com/subutai-io/agent/lib/fs"
	"github.com/subutai-io/agent/lib/gpg"
	"github.com/subutai-io/agent/log"
	"github.com/subutai-io/agent/config"
	"path"
)

//gpg1 --batch --passphrase {pwd} --symmetric --cipher-algo AES256 {/path/to/file}
func EncryptFile(pathToFile, password string) {
	pathToFile = strings.TrimSpace(pathToFile)
	password = strings.TrimSpace(password)

	checkArgument(pathToFile != "", "Invalid path to file")
	checkArgument(password != "", "Invalid password")

	checkCondition(fs.FileExists(pathToFile), func() {
		checkState(fs.FileExists(path.Join(config.Agent.CacheDir, pathToFile)), "File %s not found", pathToFile)
		pathToFile = path.Join(config.Agent.CacheDir, pathToFile)
	})

	destFile := pathToFile + ".gpg"
	if fs.FileExists(destFile) {
		fs.DeleteFile(destFile)
	}

	log.Check(log.ErrorLevel, "Encrypting file", gpg.EncryptFile(pathToFile, password))

	log.Info("Encrypted file to " + pathToFile + ".gpg")
}

//gpg1 --batch --passphrase {pwd} --output {/path/to/file} --decrypt {/path/to/file}
func DecryptFile(pathToSrcFile, pathToDestFile, password string) {
	pathToSrcFile = strings.TrimSpace(pathToSrcFile)
	pathToDestFile = strings.TrimSpace(pathToDestFile)
	password = strings.TrimSpace(password)

	checkArgument(pathToSrcFile != "", "Invalid path to encrypted source file")
	checkArgument(password != "", "Invalid password")

	checkCondition(fs.FileExists(pathToSrcFile), func() {
		checkState(fs.FileExists(path.Join(config.Agent.CacheDir, pathToSrcFile)), "File %s not found", pathToSrcFile)
		pathToSrcFile = path.Join(config.Agent.CacheDir, pathToSrcFile)
	})

	if pathToDestFile == "" {
		pathToDestFile = strings.TrimSuffix(pathToSrcFile, ".gpg") + "-decrypted"
	}

	if fs.FileExists(pathToDestFile) {
		fs.DeleteDir(pathToDestFile)
	}

	log.Check(log.ErrorLevel, "Decrypting file", gpg.DecryptFile(pathToSrcFile, pathToDestFile, password))

	log.Info("Decrypted file to " + pathToDestFile)
}
