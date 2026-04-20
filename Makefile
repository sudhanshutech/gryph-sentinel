build:
	mkdir -p bin
	go build -o bin/gryph-sentinel ./cmd/gryph-sentinel

test:
	go test ./...

release:
	mkdir -p dist
	GOOS=darwin GOARCH=amd64 go build -o dist/gryph-sentinel-darwin-amd64 ./cmd/gryph-sentinel
	GOOS=darwin GOARCH=arm64 go build -o dist/gryph-sentinel-darwin-arm64 ./cmd/gryph-sentinel
	GOOS=linux GOARCH=amd64 go build -o dist/gryph-sentinel-linux-amd64 ./cmd/gryph-sentinel
	GOOS=windows GOARCH=amd64 go build -o dist/gryph-sentinel-windows-amd64.exe ./cmd/gryph-sentinel
