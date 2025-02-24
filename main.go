package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"

	"go-vulnerability-scan/api"
)

func main() {

	r := mux.NewRouter()
	r.HandleFunc("/scan", api.Scan).Methods("POST")
	r.HandleFunc("/query", api.Query).Methods("POST")

	fmt.Println("Server is running on port 8080")
	log.Fatal(http.ListenAndServe(":8080", r))

}
