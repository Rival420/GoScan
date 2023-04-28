package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const maxConcurrentJobs = 50

func main() {
	if len(os.Args) != 4 {
		fmt.Println("Usage: go run scan.go [host] [startPort] [endPort]")
		os.Exit(1)
	}

	host := os.Args[1]

	startPort, err := strconv.Atoi(os.Args[2])
	if err != nil || startPort < 1 || startPort > 65535 {
		fmt.Println("Invalid startPort. Provide a valid port number between 1 and 65535.")
		os.Exit(1)
	}

	endPort, err := strconv.Atoi(os.Args[3])
	if err != nil || endPort < 1 || endPort > 65535 || endPort < startPort {
		fmt.Println("Invalid endPort. Provide a valid port number between startPort and 65535.")
		os.Exit(1)
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, maxConcurrentJobs)

	for port := startPort; port <= endPort; port++ {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(port int) {
			defer func() {
				<-semaphore
				wg.Done()
			}()

			tcp := layers.TCP{DstPort: layers.TCPPort(port)}

			packet := gopacket.NewPacket(nil, layers.LayerTypeTCP, gopacket.Default)
			packet.SetNetworkLayer(&tcp)

			buf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}
			err := gopacket.SerializeLayers(buf, opts, packet)
			if err != nil {
				log.Fatal(err)
			}

			handle, err := pcap.OpenLive(host, 65536, true, pcap.BlockForever)
			if err != nil {
				log.Fatal(err)
			}
			defer handle.Close()

			err = handle.WritePacketData(buf.Bytes())
			if err != nil {
				log.Fatal(err)
			}
			packet, _, err := handle.ZeroCopyReadPacketData()
			if err != nil {
				log.Fatal(err)
			}

			if len(packet) > 0 {
				fmt.Printf("%s:%d is open\n", host, port)
			}
		}(port)
	}

	wg.Wait()
}
