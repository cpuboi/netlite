package main

/*
A very lightweight netflow alternative

Version 1.0.4

*/
import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/cpuboi/netlite/tools"
	"github.com/google/gopacket/pcap"
)

func getArgs() (string, bool, bool, string, int, bool, bool, bool, string) {
	// This should handle alternative cache locations..
	var inputInterface = flag.String("i", "", "network `interface name`")
	var listDevices = flag.Bool("l", false, "list network interfaces")

	var printHeader = flag.Bool("p", false, "print header")
	var separatorCharacter = flag.String("s", "\t", "`separator` character")
	var memoryLifetimeSeconds = flag.Int("r", 600, "reset memory after X `seconds`\nthe memory of seen sockets gets purged and previously seen connections will get logged again.")

	var minimal = flag.Bool("m", false, "Show minimal output\n\tTimestamp is printed once in the header (if -p) followed by an increment of seconds for each connection\n\tProtocol is replaced by 0,1,2,3\n\t0=TCP, 1=UDP, 2=ICMP, 3=DNS, 4=NOT_IMPLEMENTED")
	var portScanMode = flag.Bool("portscan-mode", false, "Show port scans, only show incoming non established traffic\nConnections initiated from your client will not show in output\nIf the interface has several addresses, the first one will get used")
	var verbose = flag.Bool("v", false, "verbose mode")
	var ipOverride = flag.String("ip-override", "", "If Netlite cant detect interface address, set it here")
	flag.Parse()

	if !*listDevices && *inputInterface == "" {
		fmt.Fprintf(os.Stderr, "Select input device\n")
		os.Exit(1)
	}

	return *inputInterface, *listDevices, *printHeader, *separatorCharacter, *memoryLifetimeSeconds, *minimal, *portScanMode, *verbose, *ipOverride
}

func main() {

	var (
		snapshotLen int32         = 1500 // Only need header part of the frame
		promiscuous bool          = false
		timeout     time.Duration = 100 * time.Millisecond
	)

	inputInterface, listDevices, printHeader, separatorCharacter, memoryLifetimeSeconds, minimal, portScanMode, verbose, ipOverride := getArgs()

	// list devices

	if listDevices {
		deviceList := make([]string, 1)
		devices, err := pcap.FindAllDevs()
		tools.ErrCheck(err)
		for _, device := range devices {
			deviceList = append(deviceList, device.Name)
		}
		fmt.Println("Found devices:", deviceList)
		os.Exit(0)
	}

	var interfaceAddress string
	// Get interface address

	interfaceAddress, err := tools.GetInterfaceIpv4Addr(inputInterface, ipOverride)
	tools.ErrCheck(err)

	if verbose {
		fmt.Fprintf(os.Stderr, "Netlite started\n\nInterface:\t%s\nAddress:\t%s\n", inputInterface, interfaceAddress)
		if portScanMode {
			fmt.Fprintf(os.Stderr, "Portscan mode:\tenabled\n")
		} else {
			fmt.Fprintf(os.Stderr, "Portscan mode:\tdisabled\n")
		}
		if minimal {
			fmt.Fprintf(os.Stderr, "Minimal  mode:\tenabled\n")
		} else {
			fmt.Fprintf(os.Stderr, "Minimal  mode:\tdisabled\n")
		}
		fmt.Fprintf(os.Stderr, "\n")
	}

	// Print header
	if printHeader {
		tools.PrintHeader(portScanMode, separatorCharacter, minimal)
	}

	// Start capture
	tools.StartCapture(inputInterface, snapshotLen, promiscuous, timeout, separatorCharacter, memoryLifetimeSeconds, minimal, portScanMode, interfaceAddress)
}
