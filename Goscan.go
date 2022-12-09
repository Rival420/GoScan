package main

import (
  "fmt"
  "log"
  "os"
  "sync"

  "github.com/google/gopacket"
  "github.com/google/gopacket/layers"
  "github.com/google/gopacket/pcap"
)

func main() {
  // Check if a host was provided as an argument
  if len(os.Args) != 2 {
    fmt.Println("Usage: go run scan.go [host]")
    os.Exit(1)
  }

  // Store the host in a variable
  host := os.Args[1]

  // Use a WaitGroup to track the goroutines
  var wg sync.WaitGroup

  // Loop through ports 1-1024
  for port := 1; port <= 1024; port++ {
    // Add one to the WaitGroup counter
    wg.Add(1)

    // Launch a goroutine to scan the current port
    go func(port int) {
      // Decrement the WaitGroup counter when the goroutine finishes
      defer wg.Done()

      // Create a new TCP packet with the specified destination port
      tcp := layers.TCP{DstPort: layers.TCPPort(port)}

      // Create a new packet with the TCP layer
      packet := gopacket.NewPacket(nil, layers.LayerTypeTCP, gopacket.Default)
      packet.SetNetworkLayerForChecksum(&tcp)

      // Serialize the packet
      buf := gopacket.NewSerializeBuffer()
      opts := gopacket.SerializeOptions{
        FixLengths:       true,
        ComputeChecksums: true,
      }
      err := gopacket.SerializeLayers(buf, opts, packet)
      if err != nil {
        log.Fatal(err)
      }

      // Open a new PCAP handle for the host
      handle, err := pcap.OpenLive(host, 65536, true, pcap.BlockForever)
      if err != nil {
        log.Fatal(err)
      }
      defer handle.Close()

      // Send the packet and check if an ACK was received
      err = handle.WritePacketData(buf.Bytes())
      if err != nil {
        log.Fatal(err)
      }
      packet, _, err := handle.ZeroCopyReadPacketData()
      if err != nil {
        log.Fatal(err)
      }

      // If an ACK was received, the port is open
      if len(packet) > 0 {
        fmt.Println(fmt.Sprintf("%s:%d", host, port), "is open")
      }
    }(port)
  }

  // Wait for all goroutines to finish
  wg.Wait()
}
