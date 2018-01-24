// Package logger implements syslog server. It listening syslog port and sends logs to the InfluxDB server.
// It allows to show stored data and supports filtering for requesting it.
package logger

import (
	"fmt"
	"strings"
	"time"

	"github.com/influxdata/influxdb/client/v2"
	"gopkg.in/mcuadros/go-syslog.v2"

	"github.com/subutai-io/agent/agent/utils"
	"github.com/subutai-io/agent/log"
)

func initDB() bool {

	influx, err := utils.InfluxDbClient()

	log.Check(log.WarnLevel, "Initializing logger", err)

	if err == nil {

		defer influx.Close()

		_, err = influx.Query(client.Query{Command: `CREATE DATABASE logs;
		CREATE RETENTION POLICY "debug"  ON logs DURATION 24h  REPLICATION 1;
		CREATE RETENTION POLICY "info"   ON logs DURATION 48h  REPLICATION 1;
		CREATE RETENTION POLICY "notice" ON logs DURATION 72h  REPLICATION 1;
		CREATE RETENTION POLICY "warn"   ON logs DURATION 96h  REPLICATION 1;
		CREATE RETENTION POLICY "err"    ON logs DURATION 120h REPLICATION 1;
		CREATE RETENTION POLICY "crit"   ON logs DURATION 144h REPLICATION 1;
		CREATE RETENTION POLICY "alert"  ON logs DURATION 168h REPLICATION 1;
		CREATE RETENTION POLICY "emerg"  ON logs DURATION 192h REPLICATION 1;
		`, Database: "logs"})

		log.Check(log.WarnLevel, "Initializing log db", err)

	}

	return err == nil

}

// SyslogServer starts syslog server and parse data for sending it to InfluxDB.
//todo refactor this method
func SyslogServer() {
	go func() {
		for {
			if initDB() {
				return
			}
			time.Sleep(time.Second * 10)
		}
	}()

	//why do we store logs in influx db?
	//subutai log is never used so think of removing this
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

	//what is this?
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

		client, err := utils.InfluxDbClient()

		if err == nil {

			defer client.Close()

			client.Write(bp)
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
