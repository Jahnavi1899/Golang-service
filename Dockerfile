FROM golang:1.24-alpine AS build

WORKDIR /app

RUN apk update && apk add --no-cache sqlite-dev gcc musl-dev

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN GOARCH=amd64 go build -o main main.go

FROM alpine:latest

RUN apk add --no-cache sqlite-libs

WORKDIR /root/

COPY --from=build /app/main .

COPY scans.db .

RUN chmod +x /root/main

EXPOSE 8080

CMD ["./main"]
