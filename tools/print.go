package tools

import (
	"fmt"
	"strconv"
	"time"
)

// Print the header
func PrintHeader(portScanMode bool, separatorCharacter string, minimal bool) {
	var header string
	var ts string

	if minimal {
		ts = strconv.Itoa(int(time.Now().Unix()))
	} else {
		ts = "Timestamp"
	}
	if portScanMode {
		header = "SrcIP" + separatorCharacter + "DstPort" + separatorCharacter + "Proto" + separatorCharacter + ts
	} else {
		header = "SrcIP" + separatorCharacter + "SrcPort" + separatorCharacter + "DstIP" + separatorCharacter + "DstPort" + separatorCharacter + "Proto" + separatorCharacter + ts
	}
	fmt.Println(header)
}

// Print packet information, return true if packet was printed
func PrintPacketInfo(p *PacketStruct, memoryHashmap map[uint64]bool, blacklistHashmap map[uint64]bool, t int64, sep string, minimal bool, portScanMode bool, portScanWaitTimestamp int, interfaceAddress string) {
	if p.srcIp != nil { // If packet contains IP addresses
		if DestinationIsUnicast(p) { // Only allow traffic that is unicast
			if portScanMode { // Only show incoming connection attempts
				if int(time.Now().Unix()) > portScanWaitTimestamp {
					if !IpIsEstablished(p, blacklistHashmap, interfaceAddress) { // If Destination IP not in blacklist then print line (destination ip gets added to blacklist)
						if !MiniFilter(p, memoryHashmap) { // This is to prevent logging the same socket over and over
							fmt.Println(p.srcIp.String() + sep + strconv.Itoa(p.dstPort) + sep + p.proto + sep + strconv.Itoa(int(t)))
						}
					}
				}
			} else { // If not in Port scan detection mode, print all information
				if !MiniFilter(p, memoryHashmap) { // If data not in memory print line print line
					fmt.Println(p.srcIp.String() + sep + strconv.Itoa(p.srcPort) + sep + p.dstIp.String() + sep + strconv.Itoa(p.dstPort) + sep + p.proto + sep + strconv.Itoa(int(t)))
				}
			}
		}
	}
}
