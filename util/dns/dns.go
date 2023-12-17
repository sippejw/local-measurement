package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"

	"common/parseipportargs"
	"common/readfiles"

	"www.bamsoftware.com/git/dnstt.git/dns"
)

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
    %[1]s [OPTION]... [FILE]...

Description:
    Send DNS queries of domains in FILE(s) at a very fast speed. With no FILE, or when FILE is -, read standard input. The program takes a send-and-forget approach, meaning it does not capture any responses. Capture responses yourself with tcpdump or wireshark.

Examples:
    Send a type A and a type AAAA query of www.google.com to port 53 of 1.1.1.1
	echo "www.google.com" | %[1]s -dip 1.1.1.1 -type A,AAAA
    Send all 65536 types of queries of www.google.com to port 53 of 1.1.1.1
	echo "www.google.com" | %[1]s -dip 1.1.1.1 -type 0-65535
    Send DNS queries of domains in domains_1.txt and domains_2.txt, to port 53 of either 1.1.1.1 or 8.8.8.8, but not both.
	%[1]s -dip 1.1.1.1,8.8.8.8 domains_1.txt domains_2.txt

Options:
`, os.Args[0])
	flag.PrintDefaults()
}

func query(transport *net.UDPConn, remoteUDPAddr net.UDPAddr, labels [][]byte, RRType uint16) error {
	name, err := dns.NewName(labels)
	if err != nil {
		return err
	}

	// var id uint16
	// binary.Read(rand.Reader, binary.BigEndian, &id)
	query := &dns.Message{
		ID:    0x0000,
		Flags: 0x0100, // QR = 0, RD = 1
		Question: []dns.Question{
			{
				Name:  name,
				Type:  RRType,
				Class: dns.ClassIN,
			},
		},
	}
	buf, err := query.WireFormat()
	if err != nil {
		return err
	}

	_, err = transport.WriteToUDP(buf, &remoteUDPAddr)
	return err
}

func worker(id int, remoteUDPAddrs []net.UDPAddr, jobs chan string, RRTypes []uint16) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		log.Println(err)
	}

	numAddrs := len(remoteUDPAddrs)
	counter := -1

	for j := range jobs {
		for _, RRType := range RRTypes {
			log.Printf("worker %v is sending type %v query of: %v\n", id, RRType, j)
			for {
				counter++
				counter %= numAddrs
				remoteUDPAddr := remoteUDPAddrs[counter]

				q := bytes.Split([]byte(j), []byte("."))
				err := query(conn, remoteUDPAddr, q, RRType)
				if err != nil {
					if err.Error() == "name contains a label longer than 63 octets" {

					} else {
						log.Println(err.Error(), j)
						// comment out to avoid infinite loop when unexpected error
						// continue
					}
				}
				break
			}
		}
	}
}

func main() {
	flag.Usage = usage
	var port int
	var maxNumWorkers int
	ipArg := flag.String("dip", "127.0.0.1", "comma-separated list of destination IP addresses to which the program sends DNS queries. eg. 1.1.1.1,2.2.2.2")
	RRTypeArg := flag.String("type", "A", "comma-separated list of DNS RR Type of the DNS queries. eg. A,AAAA,16-18")
	flag.IntVar(&port, "p", 53, "the port to which the program sends DNS queries.")
	flag.IntVar(&maxNumWorkers, "worker", 100, "number of workers in parallel.")
	logFile := flag.String("log", "", "log to file. (default stderr)")
	flag.Parse()

	// log, intentionally make it blocking to make sure it got
	// initliazed before other parts using it
	if *logFile != "" {
		f, err := os.Create(*logFile)
		if err != nil {
			log.Panicln("failed to open log file", err)
		}
		defer f.Close()
		log.SetOutput(f)
	}

	ips, err := parseipportargs.ParseIPArgs(*ipArg)
	if err != nil {
		log.Panic(err)
	}

	RRTypes, err := parseipportargs.ParseRRTypeArgs(*RRTypeArg)
	if err != nil {
		log.Panic(err)
	}

	err = parseipportargs.ValidatePortRange(port)
	if err != nil {
		log.Panic(err)
	}

	remoteUDPAddrs := make([]net.UDPAddr, 0)
	for _, ip := range ips {
		remoteUDPAddr := net.UDPAddr{IP: ip, Port: port}
		remoteUDPAddrs = append(remoteUDPAddrs, remoteUDPAddr)
	}

	// The channel capacity does not have to be equal to the
	// number of workers. It can be smaller.
	jobs := make(chan string, 100)
	lines := readfiles.ReadFiles(flag.Args())

	go func() {
		for line := range lines {
			// we can do more parsing of the lines if needed
			// jobs are the domains to be tested
			jobs <- line
		}
		close(jobs)
	}()

	var wg sync.WaitGroup
	wg.Add(maxNumWorkers)
	for id := 0; id < maxNumWorkers; id++ {
		go func(id int) {
			defer wg.Done()
			worker(id, remoteUDPAddrs, jobs, RRTypes)
		}(id)
	}
	wg.Wait()
}
