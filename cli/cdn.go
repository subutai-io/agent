package cli

import (
	"strings"
	"github.com/subutai-io/agent/lib/fs"
	"github.com/subutai-io/agent/config"
	"github.com/subutai-io/agent/agent/util"
	"github.com/subutai-io/agent/log"
	"io/ioutil"
	"fmt"
	"regexp"
	"github.com/cavaliercoder/grab"
	"time"
	"path"
	"gopkg.in/cheggaaa/pb.v1"
	"mime/multipart"
	"os"
	"io"
	"sync"
	"net/http"
	"path/filepath"
)

func DownloadRawFile(id, destDir string) error {

	id = strings.TrimSpace(id)
	destDir = strings.TrimSpace(destDir)

	checkArgument(id != "", "Invalid file id")
	checkArgument(destDir != "", "Invalid destination directory")
	checkState(fs.FileExists(destDir), "Destination directory %s not found", destDir)

	//get file info from CDN
	theUrl := config.CdnUrl + "/raw?id=" + id

	clnt := util.GetClient(config.CDN.AllowInsecure, 30)

	response, err := util.RetryGet(theUrl, clnt, 3)

	log.Check(log.ErrorLevel, "Retrieving file info, get: "+theUrl, err)
	defer util.Close(response)

	if response.StatusCode == 404 {
		log.Error("File " + id + " not found")
	}
	if response.StatusCode != 200 {
		log.Error("Failed to get file info:  " + response.Status)
	}
	body, err := ioutil.ReadAll(response.Body)
	log.Check(log.ErrorLevel, "Reading file info", err)

	fileInfo := string(body)

	rx := regexp.MustCompile(`"id"\s*:\s*"(?P<id>[a-zA-Z0-9]+)"[\s\S]+"filename"\s*:\s*"(?P<name>.*)"`)

	checkArgument(rx.MatchString(fileInfo), "Failed to parse file id and name from:\n%s", fileInfo)

	groups := util.MatchRegexGroups(rx, fileInfo)

	fileId := groups["id"]
	fileName := groups["name"]

	//download file from IPFS
	log.Check(log.ErrorLevel, "Downloading file "+fileName, downloadFile(fileId, fileName, destDir))

	log.Info("File " + fileName + " downloaded to " + destDir)

	return nil
}

//todo implement version for downloading via local ipfs node
func downloadFile(fileId, fileName, destDir string) error {

	destFile := path.Join(destDir, fileName)

	fileUrl := strings.Replace(config.CDN.TemplateDownloadUrl, "{ID}", fileId, 1) + "/" + fileName

	// create client
	client := grab.NewClient()

	req, err := grab.NewRequest(destFile, fileUrl)

	if log.Check(log.DebugLevel, fmt.Sprintf("Preparing request %v", req.URL()), err) {
		return err
	}

	log.Info("Downloading " + fileName)

	// start download
	resp := client.Do(req)

	if resp.HTTPResponse != nil {
		log.Debug("Http status ", resp.HTTPResponse.Status)
	}

	// start UI loop
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()

	bar := pb.New(int(resp.Size)).SetUnits(pb.U_BYTES)
	if resp.Size <= 0 {
		bar.NotPrint = true
	}
	bar.Start()
	defer bar.Finish()
Loop:
	for {
		select {
		case <-t.C:
			bar.Set(int(resp.BytesComplete()))

		case <-resp.Done:
			// download is complete
			bar.Set(int(resp.BytesComplete()))
			break Loop
		}
	}

	bar.Finish()

	// check for errors
	if log.Check(log.DebugLevel, "Checking download status", resp.Err()) {
		return err
	}

	return nil
}

func UploadRawFile(filePath, cdnToken string) error {

	filePath = strings.TrimSpace(filePath)
	cdnToken = strings.TrimSpace(cdnToken)

	checkArgument(filePath != "", "Invalid file path")
	checkArgument(cdnToken != "", "Invalid token")
	checkState(fs.FileExists(filePath), "File %s not found", filePath)

	out, err := uploadFile(filePath, cdnToken)
	log.Check(log.ErrorLevel, "Uploading file "+filePath, err)

	log.Info("File " + filepath.Base(filePath) + " uploaded to CDN:\n" + out)

	return nil
}

func uploadFile(filePath, token string) (string, error) {

	file, err := os.Open(filePath)
	if log.Check(log.DebugLevel, "Opening file for upload", err) {
		return "", err
	}
	defer file.Close()

	fStat, err := file.Stat()
	if log.Check(log.DebugLevel, "Getting file size", err) {
		return "", err
	}

	bar := pb.New64(fStat.Size()).SetUnits(pb.U_BYTES).SetRefreshRate(time.Millisecond * 10)
	bar.Start()
	defer bar.Finish()

	r, w := io.Pipe()
	mpw := multipart.NewWriter(w)
	wg := sync.WaitGroup{}
	wg.Add(1)

	//feed file in a routine
	go func() {
		var part io.Writer
		defer wg.Done()
		defer bar.Finish()
		defer file.Close()
		defer w.Close()

		if err = mpw.WriteField("token", token); err != nil {
			w.CloseWithError(err)
		}

		if part, err = mpw.CreateFormFile("file", fStat.Name()); err != nil {
			w.CloseWithError(err)
		}
		part = io.MultiWriter(part, bar)
		if _, err = io.Copy(part, file); err != nil {
			w.CloseWithError(err)
		}
		if err = mpw.Close(); err != nil {
			w.CloseWithError(err)
		}
	}()

	resp, err := http.Post(config.CdnUrl+"/raw/upload", mpw.FormDataContentType(), r)

	wg.Wait()

	if log.Check(log.DebugLevel, "Checking upload status", err) {
		return "", err
	}
	defer util.Close(resp)

	out, err := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP status: %s; %s; %v", resp.Status, out, err)
	}

	return string(out), nil
}
