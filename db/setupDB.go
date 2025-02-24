package database

import (
	"database/sql"
	"fmt"
)

func InitDB(dbPath string) (*sql.DB, error) {
	// Create a new SQLite database
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, err
}

func CreateTable(db *sql.DB) error {
	// Check if a table already exists and delet if it exists
	dropQuery := "DROP TABLE IF EXISTS VulnerabilityScan;"
	_, err := db.Exec(dropQuery)
	if err != nil {
		return fmt.Errorf("error dropping table: %w", err)
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
		return fmt.Errorf("error creating table: %w", err)
	}

	return nil
}
