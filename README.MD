# Go Vulnerability Scan

This repository contains a Go-based application for scanning and querying vulnerability data from JSON files stored in a GitHub repository.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [Testing](#testing)
- [Docker](#docker)
- [Folder Structure](#folder-structure)
- [License](#license)

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/go-vulnerability-scan.git
    ```
2. Navigate to the project directory:
    ```sh
    cd go-vulnerability-scan
    ```
3. Install dependencies:
    ```sh
    go mod tidy
    ```
4. Build the project:
    ```sh
    go build -o main main.go
    ```

## Usage

1. Run the application:
    ```sh
    ./main
    ```
2. The server will start on port `8080`.

## API Endpoints

### Scan Endpoint

- **URL:** `/scan`
- **Method:** `POST`
- **Description:** Fetches vulnerability data from the specified GitHub repository and stores it in the database.
- **Request Body:**
    ```json
    {
        "repo": "https://github.com/yourusername/vulnerability_scans",
        "files": ["vulnscan1011.json", "vulnscan15.json"]
    }
    ```
- **Response:**
    ```json
    [
        {
            "scanResults": [...],
            "sourceFile": "vulnscan1011.json",
            "scanTime": "2025-02-21T17:05:12.441572-05:00"
        },
        ...
    ]
    ```

### Query Endpoint

- **URL:** `/query`
- **Method:** `POST`
- **Description:** Queries the database for vulnerabilities based on the specified filters.
- **Request Body:**
    ```json
    {
        "filters": {
            "severity": "HIGH"
        }
    }
    ```
- **Response:**
    ```json
    [
        {
            "id": "CVE-2024-2222",
            "severity": "HIGH",
            "cvss": 8.2,
            "status": "active",
            "package_name": "spring-security",
            "current_version": "5.6.0",
            "fixed_version": "5.6.1",
            "description": "Authentication bypass in Spring Security",
            "published_date": "2025-01-27T00:00:00Z",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-2222",
            "risk_factors": ["Authentication Bypass", "High CVSS Score", "Proof of Concept Exploit Available"]
        },
    ]
    ```

## Testing

To run tests for this project, follow these steps:

1. Navigate to the project directory:
    ```sh
    cd go-vulnerability-scan
    ```
2. Run the tests:
    ```sh
    go test ./...
    ```

This will execute all the tests in the project and display the results.

## Docker

To run the application using Docker, follow these steps:

1. Build the Docker image:
    ```sh
    docker build -t go-vulnerability-scan .
    ```
2. Run the Docker container:
    ```sh
    docker run -p 8080:8080 go-vulnerability-scan
    ```

The server will start on port `8080`.

## Folder Structure
```
go-vulnerability-scan/ ├── api/ │ ├── api.go │ ├── api_test.go ├── config/ │ ├── config.go ├── db/ │ ├── db.go │ ├── db_test.go ├── main.go ├── Dockerfile ├── go.mod ├── go.sum ├── README.md
```
