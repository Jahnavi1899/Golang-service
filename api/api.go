package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"go-vulnerability-scan/config"
	database "go-vulnerability-scan/db"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

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

func fetchGithubData(repo ScanBody) ([]*PayloadData, error) {
	githubURL := strings.TrimPrefix(repo.Repo, "https://github.com/")
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/contents", githubURL)
	// u := "https://api.github.com/repos/velancio/vulnerability_scans/contents"
	var resp *http.Response
	var err error

	// for retrying GitHub API calls for failed attempts
	for attempts := 0; attempts < 2; attempts++ {
		resp, err = http.Get(apiURL)
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		}
		if attempts < 1 {
			time.Sleep(5 * time.Second) // wait for 5 seconds before retrying
		}
		if err != nil {
			return nil, err
		}
	}

	if resp == nil {
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
	var mu sync.Mutex
	var wg sync.WaitGroup

	// concurrent processing of files
	for _, content := range contents {
		if content.Type == "file" && content.Name[len(content.Name)-5:] == ".json" {
			if len(repo.Files) > 0 {
				found := false
				for _, f := range repo.Files {
					if f == content.Name {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}
			wg.Add(1)
			go func(content RepoContent) {
				defer wg.Done()
				data, err := fetchFileContent(content.Name, content.DownloadURL)
				if err != nil {
					log.Printf("error fetching file content: %s", err)
					return
				}
				mu.Lock()
				allPayloadData = append(allPayloadData, data...)
				mu.Unlock()
			}(content)

		}
	}
	wg.Wait()
	return allPayloadData, nil
}

func queryJSONData(db *sql.DB, severity string) []Vulnerability {

	res := []Vulnerability{}

	rows, err := db.Query("SELECT id, source_file, scan_time, json_payload FROM VulnerabilityScan")
	if err != nil {
		log.Fatalf("error: %s", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var sourceFile, scanTime, jsonPayload string
		err = rows.Scan(&id, &sourceFile, &scanTime, &jsonPayload)
		if err != nil {
			log.Fatalf("error: %s", err)
		}

		var payload interface{}
		if err := json.Unmarshal([]byte(jsonPayload), &payload); err != nil {
			log.Fatalf("error: %s", err)
		}

		if vulnerabilities, ok := payload.([]interface{}); ok {
			for _, v := range vulnerabilities {
				if vuln, ok := v.(map[string]interface{}); ok {
					if vulnSeverity, ok := vuln["severity"].(string); ok && vulnSeverity == severity {

						id, _ := vuln["id"].(string)
						severity, _ := vuln["severity"].(string)
						cvss, _ := vuln["cvss"].(float64)
						status, _ := vuln["status"].(string)
						package_name, _ := vuln["package_name"].(string)
						current_version, _ := vuln["current_version"].(string)
						fixed_version, _ := vuln["fixed_version"].(string)
						description, _ := vuln["description"].(string)
						published_date, _ := vuln["published_date"].(string)
						link, _ := vuln["link"].(string)

						var riskFactors []string
						if rawRiskFactors, ok := vuln["risk_factors"].([]interface{}); ok {
							for _, rf := range rawRiskFactors {
								if str, ok := rf.(string); ok {
									riskFactors = append(riskFactors, str)
								}
							}
						}
						res = append(res, Vulnerability{
							Id:             id,
							Severity:       severity,
							Cvss:           cvss,
							Status:         status,
							PackageName:    package_name,
							CurrentVersion: current_version,
							FixedVersion:   fixed_version,
							Description:    description,
							PublishedDate:  published_date,
							Link:           link,
							RiskFactors:    riskFactors,
						})
					}
				}
			}
		}
	}

	err = rows.Err()
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	return res
}

func loadPayloadDb(db *sql.DB, data *PayloadData) error {
	jsonData, err := json.Marshal(data.JsonPayload)
	if err != nil {
		return fmt.Errorf("error marshaling JSON: %w", err)
	}
	_, err = db.Exec("INSERT INTO VulnerabilityScan (source_file, scan_time, json_payload) VALUES (?, ?, ?)",
		data.SourceFile, data.ScanTime.Format(time.RFC3339), string(jsonData))
	if err != nil {
		return fmt.Errorf("error inserting JSON: %w", err)
	}

	return nil
}

func Scan(ep http.ResponseWriter, r *http.Request) {
	var scanRequest ScanBody
	err := json.NewDecoder(r.Body).Decode(&scanRequest)
	if err != nil {
		http.Error(ep, err.Error(), http.StatusBadRequest)
		return
	}
	resp, err := fetchGithubData(scanRequest)
	if err != nil {
		http.Error(ep, err.Error(), http.StatusInternalServerError)
		return
	}

	db, err := database.InitDB(config.DatabasePath)
	if err != nil {
		http.Error(ep, err.Error(), http.StatusInternalServerError)
		return
	}
	if db == nil {
		http.Error(ep, "Database connection is nil", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	if err := database.CreateTable(db); err != nil {
		http.Error(ep, err.Error(), http.StatusInternalServerError)
		return
	}

	for _, data := range resp {
		if err := loadPayloadDb(db, data); err != nil {
			http.Error(ep, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	ep.Header().Set("Content-Type", "application/json")
	json.NewEncoder(ep).Encode(resp)
}

func Query(ep http.ResponseWriter, r *http.Request) {
	var queryRequest QueryRequest
	err := json.NewDecoder(r.Body).Decode(&queryRequest)
	if err != nil {
		http.Error(ep, err.Error(), http.StatusBadRequest)
		return
	}
	db, err := database.InitDB(config.DatabasePath)
	if err != nil {
		http.Error(ep, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()
	res := queryJSONData(db, queryRequest.Filters.Severity)
	ep.Header().Set("Content-Type", "application/json")
	json.NewEncoder(ep).Encode(res)
}
