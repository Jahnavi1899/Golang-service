package api

import (
	"time"
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
	Repo  string   `json:"repo"`
	Files []string `json:"files"`
}
