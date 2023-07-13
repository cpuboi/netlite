package tools

import (
	"fmt"
	"net"
	"os"
)

// Thanks https://gist.github.com/schwarzeni/f25031a3123f895ff3785970921e962c
func GetInterfaceIpv4Addr(interfaceName string, ipOverride string) (addr string, err error) {

	// Validate ipOverride first
	if ipOverride != "" {
		if net.ParseIP(ipOverride) == nil {
			return "", fmt.Errorf("%s is not a valid IPv4 address", ipOverride)
		} else {
			return ipOverride, nil
		}
	}
	var (
		ief      *net.Interface
		addrs    []net.Addr
		ipv4Addr net.IP
	)

	if ief, err = net.InterfaceByName(interfaceName); err != nil { // get interface
		return
	}
	if addrs, err = ief.Addrs(); err != nil { // get addresses
		return
	}

	for _, addr := range addrs { // get ipv4 address and return first
		if ipv4Addr = addr.(*net.IPNet).IP.To4(); ipv4Addr != nil {
			return ipv4Addr.String(), nil
		}
	}
	if ipv4Addr == nil {
		fmt.Fprintf(os.Stderr, "Interface does not have an IPv4 address\n")
		os.Exit(1)
	}
	return ipv4Addr.String(), nil
}
