# Go Vulnerability Scan

This repository contains a Go-based application for scanning and querying the JSON files stored in a GitHub repository.

## Table of Contents

- [Installation](#installation)
- [Folder Structure](#folder-structure)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [Docker](#docker)
- [Testing](#testing)

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
## Folder Structure
```
go-vulnerability-scan/
├── api/           
│   ├── api.go      
│   ├── api_test.go 
├── config/        
│   ├── config.go   
├── db/            
│   ├── db.go       
│   ├── db_test.go  
├── main.go        
├── Dockerfile     
├── go.mod         
├── go.sum         
├── README.md      
```

## Usage

1. Run the application:
    ```sh
    ./main
    ```
2. The server will start on port `8080`.

## API Endpoints

There are two endpoints to access the service: 

### Scan Endpoint

- **URL:** `/scan`
- **Method:** `POST`
- **Description:** Fetches vulnerability data from the specified files in the GitHub repository and stores them in the database.
- **Request Body:**
    ```json
    {
        "repo": "https://github.com/velancio/vulnerability_scans",
        "files": ["vulnscan1011.json", "vulnscan15.json"]
    }
    ```
- **Response:**
    ```json
    [
        {
            "scanResults": [
                {
                    "current_version": "2.7.0",
                    "cvss": 8.5,
                    "description": "Remote code execution in TensorFlow model loading",
                    "fixed_version": "2.7.1",
                    "id": "CVE-2024-5555",
                    "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-5555",
                    "package_name": "tensorflow",
                    "published_date": "2025-01-24T00:00:00Z",
                    "risk_factors": [
                        "Remote Code Execution",
                        "High CVSS Score",
                        "Public Exploit Available",
                        "Exploit in Wild"
                    ],
                    "severity": "HIGH",
                    "status": "active"
                },
                ...
            ],
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
    for getting degree of coverage
    ```sh
    go test ./... -coverage
    ```

This will execute all the tests in the project and display the results.



