package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFetchFileContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/valid.json" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`[{"scanResults": {"vulnerabilities": [{"id": "vuln1", "severity": "HIGH"}]}, "sourceFile": "file1", "scanTime": "2020-01-01T00:00:00Z"}]`))
		} else if r.URL.Path == "/invalid.json" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"scanResults": {"vulnerabilities": [{"id": "vuln1", "severity": "HIGH"}]}, "sourceFile": "file1", "scanTime": "2020-01-01T00:00:00Z"}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	tests := []struct {
		filename string
		url      string
		wantErr  bool
	}{
		{"valid.json", server.URL + "/valid.json", false},
		{"invalid.json", server.URL + "/invalid.json", false},
		{"notfound.json", server.URL + "/notfound.json", true},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			data, err := fetchFileContent(tt.filename, tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("fetchFileContent() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(data) == 0 {
				t.Errorf("fetchFileContent() returned no data")
			}
		})
	}
}

func TestFetchGithubData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/contents" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`[{"name": "valid.json", "path": "valid.json", "url": "http://example.com/valid.json", "type": "file", "download_url": "http://example.com/valid.json"}]`))
		} else if r.URL.Path == "/valid.json" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`[{"scanResults": {"vulnerabilities": [{"id": "vuln1", "severity": "HIGH"}]}, "sourceFile": "file1", "scanTime": "2020-01-01T00:00:00Z"}]`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	data, err := fetchGithubData(server.URL + "/contents")
	if err != nil {
		t.Fatalf("fetchGithubData() error = %v", err)
	}
	if len(data) == 0 {
		t.Errorf("fetchGithubData() returned no data")
	}
}

func TestLoadPayloadDb(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	createTable := `
		CREATE TABLE IF NOT EXISTS VulnerabilityScan (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			source_file TEXT NOT NULL,
			scan_time TEXT NOT NULL,
			json_payload TEXT
		);`
	_, err = db.Exec(createTable)
	if err != nil {
		t.Fatalf("failed to create table: %v", err)
	}

	payloadData := &PayloadData{
		JsonPayload: map[string]interface{}{
			"vulnerabilities": []interface{}{
				map[string]interface{}{
					"id":       "vuln1",
					"severity": "HIGH",
				},
			},
		},
		SourceFile: "file1",
		ScanTime:   time.Now(),
	}

	loadPayloadDb(db, payloadData)

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM VulnerabilityScan").Scan(&count)
	if err != nil {
		t.Fatalf("failed to query table: %v", err)
	}

	if count != 1 {
		t.Errorf("expected 1 row in VulnerabilityScan table, got %d", count)
	}
}

func TestQueryJSONData(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	createTable := `
		CREATE TABLE IF NOT EXISTS VulnerabilityScan (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			source_file TEXT NOT NULL,
			scan_time TEXT NOT NULL,
			json_payload TEXT
		);`
	_, err = db.Exec(createTable)
	if err != nil {
		t.Fatalf("failed to create table: %v", err)
	}

	payloadData := &PayloadData{
		JsonPayload: map[string]interface{}{
			"vulnerabilities": []interface{}{
				map[string]interface{}{
					"id":       "vuln1",
					"severity": "HIGH",
				},
			},
		},
		SourceFile: "file1",
		ScanTime:   time.Now(),
	}

	loadPayloadDb(db, payloadData)

	vulnerabilities := queryJSONData("HIGH")
	if len(vulnerabilities) != 1 {
		t.Errorf("expected 1 vulnerability, got %d", len(vulnerabilities))
	}
}

func TestScanHandler(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/contents" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`[{"name": "valid.json", "path": "valid.json", "url": "http://example.com/valid.json", "type": "file", "download_url": "http://example.com/valid.json"}]`))
		} else if r.URL.Path == "/valid.json" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`[{"scanResults": {"vulnerabilities": [{"id": "vuln1", "severity": "HIGH"}]}, "sourceFile": "file1", "scanTime": "2020-01-01T00:00:00Z"}]`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	req := httptest.NewRequest("POST", "/scan", nil)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(scan)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	if rr.Body.Len() == 0 {
		t.Errorf("handler returned empty body")
	}
}

func TestQueryHandler(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	createTable := `
		CREATE TABLE IF NOT EXISTS VulnerabilityScan (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			source_file TEXT NOT NULL,
			scan_time TEXT NOT NULL,
			json_payload TEXT
		);`
	_, err = db.Exec(createTable)
	if err != nil {
		t.Fatalf("failed to create table: %v", err)
	}

	payloadData := &PayloadData{
		JsonPayload: map[string]interface{}{
			"vulnerabilities": []interface{}{
				map[string]interface{}{
					"id":       "vuln1",
					"severity": "HIGH",
				},
			},
		},
		SourceFile: "file1",
		ScanTime:   time.Now(),
	}

	loadPayloadDb(db, payloadData)

	req := httptest.NewRequest("POST", "/query", nil)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(query)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	if rr.Body.Len() == 0 {
		t.Errorf("handler returned empty body")
	}
}
