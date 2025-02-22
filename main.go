package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
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

type Vulnerability struct {
	Id             string   `json:"id"`
	Severity       string   `json:"severity"`
	Cvss           float64  `json:"cvss"`
	Status         string   `json:"status"`
	PackageName    string   `json:"package_name"`
	CurrentVersion string   `json:"current_version"`
	FixedVersion   string   `json:"fixed_version"`
	Description    string   `json:"description"`
	PublishedDate  string   `json:"published_date"`
	Link           string   `json:"link"`
	RiskFactors    []string `json:"risk_factors"`
}
type Filters struct {
	Severity string `json:"severity"`
}

type QueryRequest struct {
	Filters Filters `json:"filters"`
}

type ScanBody struct {
	Repo string `json:"repo"`
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

func fetchGithubData(repo string) ([]*PayloadData, error) {
	// u := "https://api.github.com/repos/velancio/vulnerability_scans/contents"
	var resp *http.Response
	var err error

	for attempts := 0; attempts < 2; attempts++ {
		resp, err = http.Get(repo)
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

	for _, content := range contents {
		if content.Type == "file" && content.Name[len(content.Name)-5:] == ".json" {
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

func queryJSONData(severity string) []Vulnerability {
	db, err := sql.Open("sqlite3", "./scans.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
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

func loadPayloadDb(db *sql.DB, data *PayloadData) {
	jsonData, err := json.Marshal(data.JsonPayload)
	if err != nil {
		log.Fatalf("error: %s", err)
	}
	_, err = db.Exec("INSERT INTO VulnerabilityScan (source_file, scan_time, json_payload) VALUES (?, ?, ?)",
		data.SourceFile, data.ScanTime.Format(time.RFC3339), string(jsonData))
	if err != nil {
		log.Fatalf("error: %s", err)
	}
}

func scan(ep http.ResponseWriter, r *http.Request) {
	var scanRequest ScanBody
	err := json.NewDecoder(r.Body).Decode(&scanRequest)
	if err != nil {
		http.Error(ep, err.Error(), http.StatusBadRequest)
		return
	}
	resp, err := fetchGithubData(scanRequest.Repo)
	if err != nil {
		http.Error(ep, err.Error(), http.StatusInternalServerError)
		return
	}
	db, err := sql.Open("sqlite3", "./scans.db")
	if err != nil {
		http.Error(ep, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	for _, data := range resp {
		loadPayloadDb(db, data)
	}

	ep.Header().Set("Content-Type", "application/json")
	json.NewEncoder(ep).Encode(resp)
}

func query(ep http.ResponseWriter, r *http.Request) {
	var queryRequest QueryRequest
	err := json.NewDecoder(r.Body).Decode(&queryRequest)
	if err != nil {
		http.Error(ep, err.Error(), http.StatusBadRequest)
		return
	}
	res := queryJSONData(queryRequest.Filters.Severity)
	ep.Header().Set("Content-Type", "application/json")
	json.NewEncoder(ep).Encode(res)
}

func main() {

	db, err := sql.Open("sqlite3", "./scans.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	dropQuery := "DROP TABLE IF EXISTS VulnerabilityScan;"
	_, err = db.Exec(dropQuery)
	if err != nil {
		log.Fatal("Error dropping table:", err)
	}
	fmt.Print("Table dropped\n")

	createTable := `
    CREATE TABLE IF NOT EXISTS VulnerabilityScan (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_file TEXT NOT NULL,
        scan_time TEXT NOT NULL,
		json_payload TEXT
    );`

	_, err = db.Exec(createTable)
	if err != nil {
		log.Fatal(err)
	}

	r := mux.NewRouter()
	r.HandleFunc("/scan", scan).Methods("POST")
	r.HandleFunc("/query", query).Methods("POST")

	fmt.Println("Server is running on port 8080")
	log.Fatal(http.ListenAndServe(":8080", r))

}
