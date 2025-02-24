package api

import (
	"bytes"
	// "encoding/json"
	// "errors"
	"net/http"
	"net/http/httptest"
	"testing"

	// "database/sql"

	"go-vulnerability-scan/config"
	database "go-vulnerability-scan/db"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
)

// Test Scan function
func TestScan(t *testing.T) {
	tests := []struct {
		name         string
		body         string
		expectedCode int
	}{
		{
			name:         "Valid Request",
			body:         `{"repo":"https://github.com/velancio/vulnerability_scans", "files":["vulnscan1011.json", "vulnscan15.json"]}`,
			expectedCode: http.StatusOK,
		},
		{
			name:         "Invalid JSON Request",
			body:         `{invalid}`,
			expectedCode: http.StatusBadRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Initialize the database
			testDatabasePath := config.TestDB
			db, err := database.InitDB(testDatabasePath)
			if err != nil {
				t.Fatalf("error initializing database: %v", err)
			}
			defer db.Close()

			// Create the table
			err = database.CreateTable(db)
			if err != nil {
				t.Fatalf("error creating table: %v", err)
			}

			req := httptest.NewRequest("POST", "/scan", bytes.NewBufferString(test.body))
			req.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()

			// Create a new router and register the Scan handler
			router := mux.NewRouter()
			router.HandleFunc("/scan", Scan).Methods("POST")

			// Serve the HTTP request
			router.ServeHTTP(rec, req)

			// Assert status code
			if rec.Code != test.expectedCode {
				t.Errorf("expected %d, got %d", test.expectedCode, rec.Code)
			}
		})
	}
}

func TestQuery(t *testing.T) {
	tests := []struct {
		name         string
		body         string
		expectedCode int
	}{
		{
			name:         "Valid Request",
			body:         `{"filters":{"severity":"HIGH"}}`,
			expectedCode: http.StatusOK,
		},
		{
			name:         "Invalid JSON Request",
			body:         `{invalid}`,
			expectedCode: http.StatusBadRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Initialize the database
			testDatabasePath := config.TestDB
			db, err := database.InitDB(testDatabasePath)
			if err != nil {
				t.Fatalf("error initializing database: %v", err)
			}
			defer db.Close()

			// Create the table
			err = database.CreateTable(db)
			if err != nil {
				t.Fatalf("error creating table: %v", err)
			}

			req := httptest.NewRequest("POST", "/query", bytes.NewBufferString(test.body))
			req.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()

			// Create a new router and register the Query handler
			router := mux.NewRouter()
			router.HandleFunc("/query", Query).Methods("POST")

			// Serve the HTTP request
			router.ServeHTTP(rec, req)

			// Assert status code
			if rec.Code != test.expectedCode {
				t.Errorf("expected %d, got %d", test.expectedCode, rec.Code)
			}
		})
	}
}
