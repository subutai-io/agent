package fs

import (
	"io"
	"os"
	"github.com/subutai-io/agent/log"
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"path/filepath"
)

// Copy creates a copy of passed "source" file to "dest" file
func Copy(source string, dest string) error {
	sf, err := os.Open(source)
	if log.Check(log.DebugLevel, "Opening file "+source, err) {
		return err
	}
	defer sf.Close()

	df, err := os.Create(dest)
	if log.Check(log.DebugLevel, "Creating file "+dest, err) {
		return err
	}
	defer df.Close()

	_, err = io.Copy(df, sf)
	if log.Check(log.FatalLevel, "Copying file "+source+" to "+dest, err) {
		return err
	}

	return nil
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

func Sha256Sum(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func DeleteFile(filePath string) error {
	return os.Remove(filePath)
}

func DeleteDir(dirPath string) error {
	return os.RemoveAll(dirPath)
}

func RemoveFilesWildcard(wildcard string) error {
	list, err := filepath.Glob(wildcard)
	if err != nil {
		return err
	}

	for _, f := range list {
		err = os.Remove(f)
		if log.Check(log.DebugLevel, "Removing file "+f, err) {
			return err
		}
	}

	return nil
}
