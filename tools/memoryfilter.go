package tools

import (
	"strconv"
)

/*
A basic version of the ignore filter
stores all rows for x minutes so duplicates do not get printed

Returns true if srcIpPort and dstIpPort has been seen before
*/
func MiniFilter(p *PacketStruct, memoryHashmap map[string]bool) bool {
	//srcIp string, srcPort int, dstIp string, dstPort int
	filterString := p.srcIp.String() + strconv.Itoa(p.srcPort) + p.dstIp.String() + strconv.Itoa(p.dstPort)
	_, exists := memoryHashmap[filterString]
	if exists { // If Source ip:port in map, check if it has connected to destionation ip : port
		return true
	} else { // srcIpPort exists but it has not conversed with dstIpPort
		memoryHashmap[filterString] = true
		return false
	}
}

/*
Create a blacklist map of outgoing IP's
This is to prevent printing established traffic

For every packet add destination IP to blacklist (unless it's the listening device's IP)

	This prevents the response from the remote server to get logged.
	If the source IP (remote server) matches an IP that has already been a destination then dont log it.

This is to be able to only show connection attempts made from the outside
*/
func IpBlacklistFilter(p *PacketStruct, blacklistMap map[string]bool, interfaceAddress string) bool {
	_, exists := blacklistMap[p.srcIp.String()] // Does the source address match a previous destination?
	if !exists {
		blacklistMap[p.dstIp.String()] = true
		if p.srcIp.String() == interfaceAddress { // If the source is the own host, return true as to not print packet information (after adding destination to blacklist)
			return true
		} else {
			return false
		}
	}
	return true
}
