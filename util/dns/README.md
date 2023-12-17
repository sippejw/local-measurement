# DNS

## Build

* build binary

```sh
make
```

* build docker images

```sh
make docker
```

On server:

```sh
sudo docker load < dnscensor.docker.tar
```

## Intro

```sh
./dnscensor -h
```

```txt
Usage:
    ./dnscensor [OPTION]... [FILE]...

Description:
    Send DNS queries of domains in FILE(s) at a very fast speed. With no FILE, or when FILE is -, read standard input. The program takes a send-and-forget approach, meaning it does not capture any responses. Capture responses yourself with tcpdump or wireshark.

Examples:
    Send a DNS query of www.google.com to port 53 of 1.1.1.1
	echo "www.google.com" | ./dnscensor -dip 1.1.1.1
    Send DNS queries of domains in domains_1.txt and domains_2.txt, to port 53 of either 1.1.1.1 or 8.8.8.8, but not both.
	./dnscensor -dip 1.1.1.1,8.8.8.8 domains_1.txt domains_2.txt

Options:
  -dip string
    	comma-separated list of destination IP addresses to which the program sends DNS queries. eg. 1.1.1.1,2.2.2.2 (default "127.0.0.1")
  -log string
    	log to file. (default stderr)
  -p int
    	the port to which the program sends DNS queries. (default 53)
  -worker int
    	number of workers in parallel. (default 100)
```

## IPv6 support

1.

```
sudo nano /etc/docker/daemon.json
{
  "ipv6": true,
  "fixed-cidr-v6": "2001:db8:1::/64"
}
```

2.

```sh
sudo systemctl restart docker
```

Note that all tutorial and official document says `sudo systemctl reload docker`, but only restart works for me.

3. Make packets from docker going out of the host machine:

`sudo ip6tables -t nat -A POSTROUTING -s 2001:db8:1::/64 ! -o docker0 -j MASQUERADE`

4. (Optional) Check dual stack is enabled:

`sudo docker run -it alpine ash -c "ip addr show dev eth0; ip route show"`

5. Example of sending queries to `2402:f000:1:404:166:111:4:100`

`echo www.youtube.com | sudo docker run --rm -i -v "$PWD/data:/app/data" -v "$PWD/pcap:/app/pcap" user/dnscensor -dip 2402:f000:1:404:166:111:4:100`
