package tools

import (
	"strconv"
)

/*
Return True if the packet is Unicast (regular IP traffic)
*/
func DestinationIsUnicast(p *PacketStruct) bool {
	if p.dstIp.IsGlobalUnicast() || p.dstIp.IsLinkLocalUnicast() {
		return true
	}
	return false
}

/*
A basic packet filter, returns True if packet is to be filtered (discarded)

	It begins with returning true for Mutlicast addresses since we want to ignore them
	It converts the protocol, port ip string to a FNV uint64hash and adds it to the map if it does not exist
		Then returns false
	If the item already exists it returns true
*/
func MiniFilter(p *PacketStruct, memoryHashmap map[uint64]bool) bool {

	filterString := p.proto + p.srcIp.String() + strconv.Itoa(p.srcPort) + p.dstIp.String() + strconv.Itoa(p.dstPort)
	uint64Hash := StringToFnvUint64(filterString)
	_, exists := memoryHashmap[uint64Hash]
	if exists {
		return true
	} else {
		memoryHashmap[uint64Hash] = true
		return false
	}
	return true // Address is not a unicast, discard
}

/*
Create a blacklist memory-map of established connections
If the source IP is the same as the host, add the destination to the memory, return true ( established )

If the source IP is not the host and not in the memory, return False (not established )

	This prevents the response from the remote server to get logged if the local server performs a software update or similar.
	If the source IP (remote server) matches an IP that has already been a destination then dont log it.
*/
func IpIsEstablished(p *PacketStruct, blacklistMap map[uint64]bool, interfaceAddress string) bool {
	//blacklistString := string(p.proto[0]) + p.srcIp.String() // WTF Wrong ?  should be destination

	if p.srcIp.String() == interfaceAddress {
		blacklistString := string(p.proto[0]) + p.dstIp.String() // Add destination ip to blacklist
		uint64Hash := StringToFnvUint64(blacklistString)
		_, exists := blacklistMap[uint64Hash]
		if !exists {
			blacklistMap[uint64Hash] = true
		}
		return true // Connection is from the source server, return true so that it will not get printed
	} else { // source ip is not host
		blacklistString := string(p.proto[0]) + p.srcIp.String() // Check if source was a previous destination (established connection)
		uint64Hash := StringToFnvUint64(blacklistString)
		_, exists := blacklistMap[uint64Hash]
		if exists { //

			return true // Connection is established, return true so that it will not get printed
		}
	}

	return false // Connection is not established, return false so that it will get printed
}
