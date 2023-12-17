# This docker build uses a 2-stage build:
# https://docs.docker.com/develop/develop-images/multistage-build/#use-multi-stage-builds
# The first stage compiles the program to a static binary; the second
# stage copies the binary to a fresh slim image for running.

# build stage
FROM golang AS build-env

## Using golang:alpine below results in a smaller image that is around
## 300MB, compared to the 1GB image by golang; however, we don't use
## it as "[t]his variant is highly experimental, and not officially
## supported by the Go project": https://hub.docker.com/_/golang
# FROM golang:alpine AS build-env
# RUN apk update && apk add --no-cache make git

WORKDIR /go/app/
COPY . .
RUN make

# final stage
FROM alpine

COPY --from=build-env /go/app/snicensor /app/

WORKDIR /app/
RUN mkdir -p data

ENTRYPOINT ["/app/snicensor"]
