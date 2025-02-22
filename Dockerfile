# Step 1: Build the Go binary
FROM golang:1.24-alpine AS build

# Set the working directory inside the container
WORKDIR /app

# Install necessary dependencies for building SQLite3 and Go with proper cross-compilation support
# RUN apk update && apk add --no-cache sqlite-dev gcc musl-dev

# Copy the go mod and sum files to cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire source code
COPY . .

# Build the Go binary, naming it 'main'
RUN GOARCH=amd64 go build -o main main.go

# Step 2: Create a minimal image
FROM alpine:latest

# # Install the necessary SQLite3 runtime library
# RUN apk add --no-cache sqlite-libs

# Set the working directory inside the container
WORKDIR /root/

# Copy the binary from the 'build' stage
COPY --from=build /app/main .

# # Copy the database file
# COPY scans.db .

# Ensure the binary is executable
RUN chmod +x /root/main

# Expose port 8080
EXPOSE 8080

# Command to run the binary
CMD ["./main"]
