package arp

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// hwType represents a network harware type.
type hwType int

// String returns a string representation of the hardware type.
func (hwt hwType) String() string {
	switch hwt {
	case hwTypeNetROM:
		return "netrom"
	case hwTypeEther:
		return "ether"
	case hwTypeEEther:
		return "eether"
	case hwTypeAX25:
		return "ax25"
	case hwTypePROnet:
		return "pronet"
	case hwTypeChaos:
		return "chaos"
	case hwTypeIEEE802:
		return "ieee802"
	case hwTypeARCnet:
		return "arcnet"
	case hwTypeAPPLEtlk:
		return "appletalk"
	case hwTypeDLCI:
		return "dlci"
	case hwTypeATM:
		return "atm"
	case hwTypeMetricom:
		return "metricom"
	case hwTypeIEEE1394:
		return "ieee1394"
	case hwTypeEUI64:
		return "eui64"
	case hwTypeInfiniBand:
		return "infiniband"
	}
	return ""
}

// // parseHWType parses a string and returns a hwType.
// func parseHWType(s string) (hwType, error) {
// 	switch s {
// 	case "netrom":
// 		return hwTypeNetROM, nil
// 	case "ether":
// 		return hwTypeEther, nil
// 	case "eether":
// 		return hwTypeEEther, nil
// 	case "ax25":
// 		return hwTypeAX25, nil
// 	case "pronet":
// 		return hwTypePROnet, nil
// 	case "chaos":
// 		return hwTypeChaos, nil
// 	case "ieee802":
// 		return hwTypeIEEE802, nil
// 	case "arcnet":
// 		return hwTypeARCnet, nil
// 	case "appletalk":
// 		return hwTypeAPPLEtlk, nil
// 	case "dlci":
// 		return hwTypeDLCI, nil
// 	case "atm":
// 		return hwTypeATM, nil
// 	case "metricom":
// 		return hwTypeMetricom, nil
// 	case "ieee1394":
// 		return hwTypeIEEE1394, nil
// 	case "eui64":
// 		return hwTypeEUI64, nil
// 	case "inifiniband":
// 		return hwTypeInfiniBand, nil
// 	}
// 	return hwTypeNetROM, fmt.Errorf("unrecognized hardware type: %s", s)
// }

// ARP protocol hardware identifiers.
const (
	// hwTypeNetROM is from KA9Q: NET/ROM pseudo.
	hwTypeNetROM hwType = 0
	// hwTypeEther is Ethernet.
	hwTypeEther hwType = 1
	// hwTypeEEther is Experimental Ethernet.
	hwTypeEEther hwType = 2
	// hwTypeAX25 is AX.25 Level 2.
	hwTypeAX25 hwType = 3
	// hwTypePROnet is PROnet token ring.
	hwTypePROnet hwType = 4
	// hwTypeChaos is Chaosnet.
	hwTypeChaos hwType = 5
	// hwTypeIEEE802 is IEEE 802.2 Ethernet/TR/TB.
	hwTypeIEEE802 hwType = 6
	// hwTypeARCnet is ARCnet.
	hwTypeARCnet hwType = 7
	// hwTypeAPPLEtlk is APPLEtalk.
	hwTypeAPPLEtlk hwType = 8
	// hwTypeDLCI is Frame Relay DLCI.
	hwTypeDLCI hwType = 15
	// hwTypeATM is ATM.
	hwTypeATM hwType = 19
	// hwTypeMetricom is Metricom STRIP (new IANA id).
	hwTypeMetricom hwType = 23
	// hwTypeIEEE1394 is IEEE 1394 IPv4 - RFC 2734.
	hwTypeIEEE1394 hwType = 24
	// hwTypeEUI64 is EUI-64.
	hwTypeEUI64 hwType = 27
	//hwTypeInfiniBand is InfiniBand.
	hwTypeInfiniBand hwType = 32
)

// cache returns ARP cache entries for the local system.
func cache(interfaces interfacesFn) (CacheEntries, error) {
	return parseCacheFile("/proc/net/arp", interfaces)
}

// parseCacheFile parses an ARP cache file and returns a CacheEntries array.
func parseCacheFile(filename string, interfaces interfacesFn) (CacheEntries, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ifaces, err := interfaces()
	if err != nil {
		return nil, err
	}

	s := bufio.NewScanner(f)
	s.Scan()

	entries := make(CacheEntries, 0)

	for s.Scan() {
		e, err := parseCacheEntry(s.Text(), ifaces)
		if err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}

	return entries, nil
}

// parseCacheEntry parases a string and returns a ARP cache *Entry.
func parseCacheEntry(s string, ifaces []net.Interface) (*CacheEntry, error) {
	// Consts for the field indexes in the ARP cache.
	const (
		f_IPAddr int = iota
		f_HWType
		f_Flags
		f_HWAddr
		f_Mask
		f_Device
	)

	// Split the ARP cache string into fields.
	fields := strings.Fields(s)

	// Parse the remote's IP address.
	ip := net.ParseIP(fields[f_IPAddr])
	if ip == nil {
		return nil, fmt.Errorf("failed to parse IP address: %s", fields[f_IPAddr])
	}

	// Parse the remote's MAC address.
	hwAddr, err := net.ParseMAC(fields[f_HWAddr])
	if err != nil {
		return nil, err
	}

	// Parse hardware type.
	hwTyp, err := strconv.ParseInt(fields[f_HWType], 0, 32)
	if err != nil {
		return nil, err
	}

	// Find the local interface which added the cache entry.
	d := fields[f_Device]
	var dev *net.Interface
	for _, iface := range ifaces {
		if iface.Name == d {
			dev = &iface
			break
		}
	}

	// Create the cache entry to return to caller.
	e := &CacheEntry{
		IP:           ip,
		HardwareAddr: hwAddr,
		HardwareType: hwType(hwTyp).String(),
		Interface:    dev,
	}

	return e, nil
}
