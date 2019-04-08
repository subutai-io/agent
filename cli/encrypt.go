package cli

import (
	"strings"
	"github.com/subutai-io/agent/lib/fs"
	"github.com/subutai-io/agent/lib/gpg"
	"github.com/subutai-io/agent/log"
)

//gpg1 --batch --passphrase {pwd} --symmetric --cipher-algo AES256 {/path/to/file}
func EncryptFile(pathToFile, password string) {
	pathToFile = strings.TrimSpace(pathToFile)
	password = strings.TrimSpace(password)

	checkArgument(pathToFile != "", "Invalid path to file")
	checkArgument(password != "", "Invalid password")

	checkState(fs.FileExists(pathToFile), "File % not found", pathToFile)

	destFile := pathToFile + ".gpg"
	if fs.FileExists(destFile) {
		fs.DeleteFile(destFile)
	}

	log.Check(log.ErrorLevel, "Encrypting file", gpg.EncryptFile(pathToFile, password))
}

//gpg1 --batch --passphrase {pwd} --output {/path/to/file} --decrypt {/path/to/file}
func DecryptFile(pathToSrcFile, pathToDestFile, password string) {
	pathToSrcFile = strings.TrimSpace(pathToSrcFile)
	pathToDestFile = strings.TrimSpace(pathToDestFile)
	password = strings.TrimSpace(password)

	checkArgument(pathToSrcFile != "", "Invalid path to encrypted source file")
	checkArgument(pathToDestFile != "", "Invalid path to decrypted target file")
	checkArgument(password != "", "Invalid password")

	checkState(fs.FileExists(pathToSrcFile), "File % not found", pathToSrcFile)

	log.Check(log.ErrorLevel, "Decrypting file", gpg.DecryptFile(pathToSrcFile, pathToDestFile, password))
}
