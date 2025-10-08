build:
	go vet
	go build
install: build
	go install
