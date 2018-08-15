package fs

import (
	"io"
	"os"
	"github.com/subutai-io/agent/log"
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

func IsDir(path string) (bool, error) {
	stat, err := os.Stat(path)

	if err != nil {
		return false, err
	}

	return stat.IsDir(), nil
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

func IsMountPoint(path string) bool {
	out, err := exec.Command("mountpoint", path).CombinedOutput()
	log.Check(log.DebugLevel, "Checking mountpoint "+string(out), err)
	return err == nil
}
