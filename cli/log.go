package cli

import (
	"fmt"
	"strconv"
	"time"

	"os"

	"strings"

	"github.com/influxdata/influxdb/client/v2"
	"github.com/subutai-io/agent/config"
)

var syslogLevels = []string{"emerg", "alert", "crit", "err", "warn", "notice", "info", "debug"}

// Log prints log information from database server.
func Log(app, level, start, end string) {
	c, err := client.NewHTTPClient(client.HTTPConfig{
		Addr:               "https://" + config.Influxdb.Server + ":8086",
		Username:           config.Influxdb.User,
		Password:           config.Influxdb.Pass,
		InsecureSkipVerify: true,
	})
	if err == nil {
		defer c.Close()
	}

	var list string
	for i := 1; i < 8; i++ {
		list += "logs." + syslogLevels[i] + ".syslog, "
		if syslogLevels[i] == level {
			break
		}
	}

	hostname, _ := os.Hostname()

	where := "hostname = '" + hostname + "'"
	if len(start) > 0 {
		where += " AND time > '" + start + "'"
	}
	if len(end) > 0 {
		where += " AND time < '" + end + "'"
	}
	if len(app) > 0 {
		where += " AND app = '" + app + "'"
	}

	res, _ := queryInfluxDB(c, "SELECT app, pid, severity, message FROM "+strings.TrimSuffix(list, ", ")+" WHERE "+where)
	if len(res) > 0 && len(res[0].Series) > 0 {
		for _, k := range res[0].Series[0].Values {
			if len(k) > 4 {
				i, _ := strconv.ParseInt(fmt.Sprint(k[0]), 10, 64)
				fmt.Printf("%s %s[%s]:%s - %s\n", time.Unix(i, 0), k[1], k[2], k[3], k[4])
			}
		}
	}
}
