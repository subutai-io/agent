package fs

import (
	"io"
	"os"

	"github.com/jhoonb/archivex"

	"github.com/subutai-io/agent/log"
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
	log.Check(log.FatalLevel, "Coping file "+source+" to "+dest, err)
}

// Tar function creates archive file of specified folder
func Tar(folder, file string) {
	archive := new(archivex.TarFile)
	archive.Create(file)
	log.Check(log.FatalLevel, "Packing file "+folder, archive.AddAll(folder, false))
	archive.Close()
}
