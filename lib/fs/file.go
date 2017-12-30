package fs

import (
	"io"
	"os"
	"path/filepath"

	"github.com/jhoonb/archivex"

	"github.com/subutai-io/agent/log"
)

// Copy creates a copy of passed "source" file to "dest" file
func Copy(source string, dest string) {
	sf, err := os.Open(source)
	defer sf.Close()
	log.Check(log.FatalLevel, "Opening file "+source, err)

	df, err := os.Create(dest)
	defer df.Close()
	log.Check(log.FatalLevel, "Creating file "+dest, err)

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

func ChownR(path string, uid, gid int) error {
	return filepath.Walk(path, func(name string, info os.FileInfo, err error) error {
		if err == nil {
			err = os.Chown(name, uid, gid)
		}
		return err
	})
}
