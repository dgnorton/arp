package arp

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
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
	IP := net.ParseIP(fields[f_IPAddr])
	if IP == nil {
		return nil, fmt.Errorf("failed to parse IP address: %s", fields[f_IPAddr])
	}

	// Parse the remote's MAC address.
	HWAddr, err := net.ParseMAC(fields[f_HWAddr])
	if err != nil {
		return nil, err
	}

	// Find the local interface which added the cache entry.
	d := fields[f_Device]
	var device *net.Interface
	for _, iface := range ifaces {
		if iface.Name == d {
			device = &iface
			break
		}
	}

	// Create the cache entry to return to caller.
	e := &CacheEntry{
		IP:           &IP,
		HardwareAddr: HWAddr,
		Interface:    device,
	}

	return e, nil
}
