package arp

import (
	"net"
)

// CacheEntries represents a list of ARP cache entries.
type CacheEntries []*CacheEntry

// CacheEntry represents an entry in the ARP cache.
type CacheEntry struct {
	IP           net.IP
	HardwareAddr net.HardwareAddr
	HardwareType string
	Interface    *net.Interface
	Flags        int
}

func Cache() (CacheEntries, error) {
	return cache(net.Interfaces)
}

type interfacesFn func() ([]net.Interface, error)
