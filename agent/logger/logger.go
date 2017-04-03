// Package logger implements syslog server. It listening syslog port and sends logs to the InfluxDB server.
// It allows to show stored data and supports filtering for requesting it.
package logger

import (
	"fmt"
	"strings"
	"time"

	client "github.com/influxdata/influxdb/client/v2"
	syslog "gopkg.in/mcuadros/go-syslog.v2"

	"github.com/subutai-io/agent/config"
)

var c client.Client

func initDB() {
	c, _ = client.NewHTTPClient(client.HTTPConfig{
		Addr:               "https://" + config.Influxdb.Server + ":8086",
		Username:           config.Influxdb.User,
		Password:           config.Influxdb.Pass,
		InsecureSkipVerify: true,
	})
	c.Query(client.Query{Command: `CREATE DATABASE logs;
		CREATE RETENTION POLICY "debug"  ON logs DURATION 24h  REPLICATION 1;
		CREATE RETENTION POLICY "info"   ON logs DURATION 48h  REPLICATION 1;
		CREATE RETENTION POLICY "notice" ON logs DURATION 72h  REPLICATION 1;
		CREATE RETENTION POLICY "warn"   ON logs DURATION 96h  REPLICATION 1;
		CREATE RETENTION POLICY "err"    ON logs DURATION 120h REPLICATION 1;
		CREATE RETENTION POLICY "crit"   ON logs DURATION 144h REPLICATION 1;
		CREATE RETENTION POLICY "alert"  ON logs DURATION 168h REPLICATION 1;
		CREATE RETENTION POLICY "emerg"  ON logs DURATION 192h REPLICATION 1;
		`, Database: "logs"})
}

// SyslogServer starts syslog server and parse data for sending it to InfluxDB.
func SyslogServer() {
	go func() {
		var err error
		initDB()
		for dbHost := config.Influxdb.Server; ; _, _, err = c.Ping(time.Second * 3) {
			if dbHost != config.Influxdb.Server || err != nil {
				initDB()
				dbHost = config.Influxdb.Server
			}
			time.Sleep(time.Second * 10)
		}
	}()

	channel := make(syslog.LogPartsChannel)
	go func(channel syslog.LogPartsChannel) {
		for logParts := range channel {
			s := strings.Split(fmt.Sprint(logParts["content"]), "]: ")
			if f := strings.Fields(s[0]); len(f) > 2 && len(s) > 1 {
				if app := strings.Split(strings.Join(f[2:], " "), "["); len(app) > 1 {
					go writeLog(f[1], app[0], fmt.Sprint(logParts["severity"]), app[1], strings.Join(s[1:], ": "))
				} else {
					go writeLog(f[1], app[0], fmt.Sprint(logParts["severity"]), "0", strings.Join(s[1:], ": "))
				}
			}
		}
	}(channel)

	for {
		if server := syslog.NewServer(); server != nil {
			server.SetFormat(syslog.Automatic)
			server.SetHandler(syslog.NewChannelHandler(channel))
			server.ListenUDP("127.0.0.1:1514")
			server.Boot()
			server.Wait()
		}
		time.Sleep(time.Second * 10)
	}
}

func writeLog(hostname, app, severity, pid, message string) {
	if bp, err := client.NewBatchPoints(client.BatchPointsConfig{Database: "logs", RetentionPolicy: resolveSeverity(severity)}); err == nil {
		point, _ := client.NewPoint("syslog",
			map[string]string{"hostname": hostname, "severity": resolveSeverity(severity), "app": app, "pid": pid},
			map[string]interface{}{"message": message},
			time.Now())
		bp.AddPoint(point)
		if c == nil || c.Write(bp) != nil {
			initDB()
		}
	}
}

func resolveSeverity(value string) (keyword string) {
	switch value {
	case "0":
		return "emerg"
	case "1":
		return "alert"
	case "2":
		return "crit"
	case "3":
		return "err"
	case "4":
		return "warn"
	case "5":
		return "notice"
	case "6":
		return "info"
	case "7":
		return "debug"
	}
	return "debug"
}
