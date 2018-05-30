package fs

import (
	"io"
	"os"
	"path/filepath"

	"github.com/jhoonb/archivex"

	"github.com/subutai-io/agent/log"
	"strings"
	"os/exec"
	"crypto/md5"
	"fmt"
)

// Copy creates a copy of passed "source" file to "dest" file
func Copy(source string, dest string) {
	sf, err := os.Open(source)
	log.Check(log.FatalLevel, "Opening file "+source, err)
	defer sf.Close()

	df, err := os.Create(dest)
	log.Check(log.FatalLevel, "Creating file "+dest, err)
	defer df.Close()

	_, err = io.Copy(df, sf)
	log.Check(log.FatalLevel, "Copying file "+source+" to "+dest, err)
}

// Tar function creates archive file of specified folder
func Tar(folder, file string) {
	archive := new(archivex.TarFile)
	archive.Create(file)
	log.Check(log.FatalLevel, "Packing file "+folder, archive.AddAll(folder, false))
	archive.Close()
}

func FileExists(name string) bool {
	_, err := os.Stat(name)

	if os.IsNotExist(err) {
		return false
	}

	//sometimes there can be permission or other errors
	//here we use a simple logic that if file exists and we can use it then true otherwise false
	return err == nil
}

func FileSize(path string) (int64, error) {
	stat, err := os.Stat(path)

	if err != nil {
		return -1, err
	}

	return stat.Size(), nil
}

// md5sum returns MD5 hash sum of specified file
func Md5Sum(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func GetFilesWildCard(wildcard string) []string {
	files, err := filepath.Glob(wildcard)

	if log.Check(log.WarnLevel, "Getting files by wildcard: "+wildcard, err) {
		return nil
	}

	return files
}

func DeleteFilesWildcard(wildcard string, excludedFiles ...string) {

	files := GetFilesWildCard(wildcard)

	if files == nil {
		return
	}

	for _, f := range files {

		exclude := false

		for _, excludedFile := range excludedFiles {
			if strings.HasSuffix(f, excludedFile) {
				exclude = true
				break
			}
		}

		if !exclude {
			log.Check(log.WarnLevel, "Removing file: "+f, os.Remove(f))
		}
	}
}

func IsMountPoint(path string) bool {
	out, err := exec.Command("mountpoint", path).CombinedOutput()
	log.Check(log.DebugLevel, "Checking mountpoint "+string(out), err)
	return err == nil
}
