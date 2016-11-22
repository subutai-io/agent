package cli

import (
	"github.com/subutai-io/agent/db"
	"github.com/subutai-io/agent/log"
)

func PortMap() {
	db, err := db.New()
	log.Check(log.FatalLevel, "Connecting to the DB", err)
	log.Check(log.FatalLevel, "Writing to the DB", db.WritePortMap("11123", "192.168.0.12:11112"))
	log.Check(log.FatalLevel, "Closing the DB", db.Close())
}
