godot:
	GOPATH=${CURDIR} go build src/godot/godot.go

clean:
	GOPATH=${CURDIR} go clean

# Go takes care of dependencies
.PHONY: godot clean
