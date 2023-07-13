package tools

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type PacketStruct struct {
	srcIp   net.IP
	dstIp   net.IP
	srcPort int
	dstPort int
	proto   string
}

// Populate the PacketStruct
func GetPacketInfo(packet gopacket.Packet, p *PacketStruct, minimal bool) {
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer != nil {
		ip, _ := ipv4Layer.(*layers.IPv4)
		p.srcIp = ip.SrcIP
		p.dstIp = ip.DstIP
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)

	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		p.srcPort = int(tcp.SrcPort)
		p.dstPort = int(tcp.DstPort)
		if minimal {
			p.proto = "0"
		} else {
			p.proto = "TCP"
		}
	} else if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		p.srcPort = int(udp.SrcPort)
		p.dstPort = int(udp.DstPort)
		if minimal {
			p.proto = "1"
		} else {
			p.proto = "UDP"
		}
	} else if icmpLayer != nil {
		p.srcPort = 0
		p.dstPort = 0
		if minimal {
			p.proto = "2"
		} else {
			p.proto = "ICMP"
		}
	}

	if dnsLayer != nil { // Check if DNS layer exists
		if minimal {
			p.proto = "3"
		} else {
			p.proto = "DNS"
		}
	}
}

func StartCapture(inputInterface string, snapshotLen int32, promiscuous bool, timeout time.Duration, separatorCharacter string, memoryLifetimeSeconds int, minimal bool, portScanMode bool, interfaceAddress string) {
	// Start time of capture
	processStartTime := time.Now().Unix()

	// Create memory hashmap
	memoryHashmap := make(map[string]bool)
	blacklistHashmap := make(map[string]bool) // For defensive port scan mode
	mapInitTime := time.Now().Unix()          // Time when map was last initialized

	// Create packet struct
	pStruct := PacketStruct{}

	// Capture packets
	pcapHandle, err := pcap.OpenLive(inputInterface, snapshotLen, promiscuous, timeout)
	ErrCheck(err)
	defer pcapHandle.Close()

	packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())
	// Check to only print real timestamp once when in minimal mode
	minimalPrintedFirstTimestamp := false
	// Process all the packets
	for packet := range packetSource.Packets() {

		// Set time of collected packet
		timeNow := time.Now().Unix()

		// Clear the map after memoryLifetimeSeconds
		if timeNow-mapInitTime > int64(memoryLifetimeSeconds) {
			memoryHashmap = make(map[string]bool)
			if portScanMode {
				blacklistHashmap = make(map[string]bool)
			}
			mapInitTime = timeNow // Update the reset timestamp
		}

		// If minimal then convert epoch to seconds since start of collection (to save space)
		if minimal {
			if minimalPrintedFirstTimestamp { // If the first packet has outputted full timestamp, then output seconds since start
				timeNow = time.Now().Unix() - processStartTime
			} else {
				minimalPrintedFirstTimestamp = true
			}

		}

		// Populate the packet struct
		GetPacketInfo(packet, &pStruct, minimal)

		// Print packet information
		PrintPacketInfo(&pStruct, memoryHashmap, blacklistHashmap, timeNow, separatorCharacter, minimal, portScanMode, interfaceAddress)
	}
}
