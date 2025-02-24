package database

import (
	"go-vulnerability-scan/config"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestInitDB(t *testing.T) {
	db, err := InitDB(config.TestDB)
	if err != nil {
		t.Fatalf("error initializing database: %v", err)
	}

	if db == nil {
		t.Fatalf("Expected a valid database, but got a nil")
	}

	db.Close()
}

func TestCreateTable(t *testing.T) {
	db, err := InitDB(config.TestDB)
	if err != nil {
		t.Fatalf("error initializing database: %v", err)
	}
	defer db.Close()

	err = CreateTable(db)
	if err != nil {
		t.Fatalf("error creating table: %v", err)
	}
}

func TestCreateTable_ClosedDB(t *testing.T) {
	db, err := InitDB(config.TestDB)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	db.Close()

	err = CreateTable(db)
	if err == nil {
		t.Fatal("Expected error when using closed database, but got none")
	}
}
