
all: clean deps tools test

clean:
	go clean -testcache

test:
	go test -coverprofile=coverage.out ./...

test-race:
	go test -race ./...

bench:
	go test -bench . ./...
