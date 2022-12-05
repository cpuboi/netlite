package tools

import (
	"strconv"
)

/*
A basic version of the ignore filter
stores all rows for x minutes so duplicates do not get printed

Returns true if srcIpPort and dstIpPort has been seen before
*/
func MiniFilter(srcIp string, srcPort int, dstIp string, dstPort int, memory map[string]bool) bool {
	filterString := srcIp + strconv.Itoa(srcPort) + dstIp + strconv.Itoa(dstPort)
	_, exists := memory[filterString]
	if exists { // If Source ip:port in map, check if it has connected to destionation ip : port
		return true
	} else { // srcIpPort exists but it has not conversed with dstIpPort
		memory[filterString] = true
		return false
	}
}
