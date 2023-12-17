# build stage
FROM golang AS build-env
WORKDIR /go/app/
COPY . .
RUN make

# final stage
FROM alpine
RUN apk add --no-cache bash tcpdump sudo

COPY --from=build-env /go/app/dnscensor /app/
COPY /run.sh /app/

WORKDIR /app/

ENTRYPOINT ["/app/run.sh"]

# sudo docker run -i -v $PWD/data:/app/data -v $PWD/pcap:/app/pcap user/dnscensor #
