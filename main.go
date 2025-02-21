package main

import (
	// "database/sql"
	// "encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
	// "net/url"
	// "os"
	// "time"
)

type PayloadData struct {
	JsonPayload interface{} `json:"scanResults"`
	SourceFile  string      `json:"sourceFile"`
	ScanTime    time.Time   `json:"scanTime"`
}

type RepoContent struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Url         string `json:"url"`
	Type        string `json:"type"`
	DownloadURL string `json:"download_url"`
}

func fetchFileContent(filename string, url string) ([]*PayloadData, error) {

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var data []*PayloadData

	if err := json.Unmarshal(body, &data); err != nil {
		var singleData PayloadData
		if err := json.Unmarshal(body, &singleData); err != nil {
			return nil, err
		}
		singleData.SourceFile = filename
		singleData.ScanTime = time.Now()
		if scanResults, ok := singleData.JsonPayload.(map[string]interface{}); ok {
			if vulnerabilities, ok := scanResults["vulnerabilities"]; ok {
				singleData.JsonPayload = vulnerabilities
			} else {
				singleData.JsonPayload = nil
			}
		} else {
			singleData.JsonPayload = nil
		}
		data = append(data, &singleData)
	} else {
		for _, d := range data {
			d.ScanTime = time.Now()
			d.SourceFile = filename
			if scanResults, ok := d.JsonPayload.(map[string]interface{}); ok {
				if vulnerabilities, ok := scanResults["vulnerabilities"]; ok {
					d.JsonPayload = vulnerabilities
				} else {
					d.JsonPayload = nil
				}
			} else {
				d.JsonPayload = nil
			}

		}
	}

	return data, nil
}

func scan() ([]*PayloadData, error) {
	u := fmt.Sprintf("https://api.github.com/repos/velancio/vulnerability_scans/contents")
	resp, err := http.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", resp.Status)
	}

	var contents []RepoContent
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&contents); err != nil {
		return nil, err
	}

	var allPayloadData []*PayloadData
	for _, content := range contents {
		// fmt.Print(content.Name)
		if content.Type == "file" && content.Name[len(content.Name)-5:] == ".json" {
			data, err := fetchFileContent(content.Name, content.DownloadURL)
			if err != nil {
				return nil, err
			}
			allPayloadData = append(allPayloadData, data...)
		}
	}

	return allPayloadData, nil
}

func loadPayloadDb(data *PayloadData) {
	jsonPayload, err := json.Marshal(data.JsonPayload)
	if err != nil {
		log.Fatalf("error: %s", err)
	}
	// Process the JSON payload here
	// fmt.Printf("Processing file: %s\n", data.Name)
	// fmt.Printf("Payload: %v\n", data.Path)
	fmt.Printf("File name: %s\n", data.SourceFile)
	fmt.Printf("File path: %s\n", string(jsonPayload))
	fmt.Printf("File URL: %s\n", data.ScanTime)
	fmt.Println("--------------------------------------------------")
}

func main() {

	resp, err := scan()
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	// for _, content := range resp {
	// 	if content.Type == "file" {
	// 		processPayload(&content)
	// 	}
	// }
	for _, data := range resp {
		loadPayloadDb(data)
	}
}
