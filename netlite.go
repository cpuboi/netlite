package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/cpuboi/netlite/tools"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type packetStruct struct {
	srcIp   net.IP
	dstIp   net.IP
	srcPort int
	dstPort int
	proto   string
}

func errCheck(err error) {
	if err != nil {
		//panic(err)
		fmt.Println("[x]", err)
		os.Exit(1)
	}
}

func getArgs() (string, bool, bool, string, int) {
	// This should handle alternative cache locations..
	var inputDevice = flag.String("i", "", "Input device")
	var listDevices = flag.Bool("l", false, "Input device")

	var printHeader = flag.Bool("p", false, "Print header")
	var separatorCharacter = flag.String("s", "	", "Separator character")
	var memoryLifetimeSeconds = flag.Int("r", 600, "Reset interval of memory, after interval seconds the memory of seen units get purged and previously seen connections will get logged again.")
	flag.Parse()
	return *inputDevice, *listDevices, *printHeader, *separatorCharacter, *memoryLifetimeSeconds
}

func printPacketInfo(p *packetStruct, m map[string]bool, t int64, separatorCharacter string) {
	//header := "sourceIp,sourcePort,destinationIp,destinationPort,protocol,timestamp"
	// First check filter
	// If packet contains IP addresses
	if p.srcIp != nil {
		if !tools.MiniFilter(p.srcIp.String(), p.srcPort, p.dstIp.String(), p.dstPort, m) { // If data not in memory print line print line
			fmt.Println(p.srcIp.String() + separatorCharacter + strconv.Itoa(p.srcPort) + separatorCharacter + p.dstIp.String() + separatorCharacter + strconv.Itoa(p.dstPort) + separatorCharacter + p.proto + separatorCharacter + strconv.Itoa(int(t)))
		} else {
		}
	}
}

func getPacketInfo(packet gopacket.Packet, p *packetStruct) {

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		p.srcIp = ip.SrcIP
		p.dstIp = ip.DstIP
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		p.srcPort = int(tcp.SrcPort)
		p.dstPort = int(tcp.DstPort)
		p.proto = "TCP"
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		p.srcPort = int(udp.SrcPort)
		p.dstPort = int(udp.DstPort)
		p.proto = "UDP"
	}

	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer != nil {
		p.proto = "DNS"
	}

	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	if icmpLayer != nil {
		p.proto = "ICMP"
	}

}

func main() {

	var (
		device       string        = ""
		snapshot_len int32         = 100 // Only need header part of the frame
		promiscuous  bool          = false
		timeout      time.Duration = 100 * time.Millisecond
		handle       *pcap.Handle
	)

	inputDevice, listDevices, printHeader, separatorCharacter, memoryLifetimeSeconds := getArgs()

	if listDevices {
		deviceList := make([]string, 1)
		devices, err := pcap.FindAllDevs()
		errCheck(err)
		for _, device := range devices {
			deviceList = append(deviceList, device.Name)
		}
		fmt.Println("[-] Found devices:", deviceList)
		os.Exit(0)
	}

	if inputDevice == "" {
		fmt.Println("[x] Select input device")
		os.Exit(1)
	} else {
		device = inputDevice
	}

	// Create memory hashmap
	m := make(map[string]bool)
	mapInitTime := time.Now().Unix()
	// Create packet struct
	p := packetStruct{}

	// Capture packets
	handle, err := pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	errCheck(err)
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	if printHeader {
		header := "sourceIP" + separatorCharacter + "srcPort" + separatorCharacter + "destinationIP" + separatorCharacter + "dstPort" + separatorCharacter + "proto" + separatorCharacter + "timestamp"
		fmt.Println(header)
	}

	for packet := range packetSource.Packets() {
		t := time.Now().Unix()
		if t-mapInitTime > int64(memoryLifetimeSeconds) { // Clear the map after memoryLifetimeSeconds so as to show previously logged connections.
			m = make(map[string]bool)
			mapInitTime = t // Store new map init time to compare to
		}
		getPacketInfo(packet, &p)
		printPacketInfo(&p, m, t, separatorCharacter)

	}
}
