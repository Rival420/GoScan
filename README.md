# GoScan
A simple and intuitive TCP port scanner written in Go. This port scanner checks if specified ports are open on a given host. The code uses the gopacket library to create and send TCP packets and capture the responses.

## Prerequisites

You will need to install go to be able to run this

To install the gopacket library, run the following command:
```bash
go get -u github.com/google/gopacket
```

## Usage

To run the TCP port scanner, use the following command:
```bash
go run scan.go [host] [startPort] [endPort]
```
Replace `[host]`, `[startPort]`, and `[endPort]` with the desired host, starting port, and ending port, respectively.

For example:
```bash
go run scan.go example.com 1 1024
```
This command will scan ports 1 through 1024 on the host `example.com`.

## Limitations

While this code is optimized in terms of speed and adaptability, it's still a basic TCP port scanner and may not be as efficient or accurate as more advanced scanners like Nmap.

Please use this tool responsibly and only scan networks or hosts you have permission to access.

