ALL = $(BIN)

# creates static binaries
LD_FLAGS := -ldflags "-w -s"
CC := CGO_ENABLED=0 go build -trimpath -a -installsuffix cgo $(LD_FLAGS)

BIN := dnscensor
SOURCES := dns.go

.PHONY: all
all: $(ALL)

docker: Dockerfile run.sh $(BIN)
	sudo docker build --tag "user/dnscensor" . --no-cache
	sudo docker save "user/dnscensor" > dnscensor.docker.tar

$(BIN): $(SOURCES) go.mod go.sum
	$(CC) -o "$@" $(SOURCES)

.PHONY: clean
clean:
	rm -f $(ALL)

.DELETE_ON_ERROR:
