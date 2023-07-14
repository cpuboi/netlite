package tools

import (
	"fmt"
	"strconv"
)

// Print the header
func PrintHeader(portScanMode bool, separatorCharacter string) {
	var header string
	if portScanMode {
		header = "SrcIP" + separatorCharacter + "DstPort" + separatorCharacter + "Proto" + separatorCharacter + "Timestamp"
	} else {
		header = "SrcIP" + separatorCharacter + "DstPort" + separatorCharacter + "Proto" + separatorCharacter + "Timestamp"
	}
	fmt.Println(header)
}

// Print packet information
func PrintPacketInfo(p *PacketStruct, memoryHashmap map[string]bool, blacklistHashmap map[string]bool, t int64, sep string, minimal bool, portScanMode bool, interfaceAddress string) {

	if p.srcIp != nil { // If packet contains IP addresses
		if portScanMode { // Only show incoming connection attempts

			if !IpBlacklistFilter(p, blacklistHashmap, interfaceAddress) { // If Destination IP not in blacklist then print line (destination ip gets added to blacklist)
				if !MiniFilter(p, memoryHashmap) { // This is to prevent logging the same socket over and over
					fmt.Println(p.srcIp.String() + sep + strconv.Itoa(p.dstPort) + sep + p.proto + sep + strconv.Itoa(int(t)))
				}
			}
		} else { // If not in Port scan detection mode, print all information
			if !MiniFilter(p, memoryHashmap) { // If data not in memory print line print line
				fmt.Println(p.srcIp.String() + sep + strconv.Itoa(p.srcPort) + sep + p.dstIp.String() + sep + strconv.Itoa(p.dstPort) + sep + p.proto + sep + strconv.Itoa(int(t)))
			}
		}
	}
}
