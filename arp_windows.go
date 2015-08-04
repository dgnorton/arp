package arp

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// cache returns ARP cache entries for the local system.
func cache(interfaces interfacesFn) (CacheEntries, error) {
	var size uint32
	// Get the size of buffer required to hold all ARP entries.
	// Note: will return error because buffer not large enough.
	_ = getIpNetTable(nil, &size, false)
	// Allocate a buffer large enough to hold all entries.
	buf := make([]byte, size)
	// Get the raw ARP table entries.
	if err := getIpNetTable(buf, &size, true); err != nil {
		return nil, err
	}

	// Unmarshal the raw data into internal struct.
	nt := &ipNetTable{}
	if err := nt.UnmarshalBinary(buf); err != nil {
		return nil, err
	}
	// Get a list of local network interfaces.
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	// Convert the internal struct to our API types.
	entries := make(CacheEntries, 0, nt.NumEntries)
	for _, row := range nt.Table {
		entry := &CacheEntry{
			IP:           inet_ntoa(row.Addr),
			HardwareAddr: row.PhysAddr[0:row.PhysAddrLen],
			Flags:        int(row.Type),
		}
		// Find the local interface that added this entry.
		for _, iface := range ifaces {
			if iface.Index == int(row.Index) {
				entry.Interface = &iface
				break
			}
		}
		entries = append(entries, entry)
	}

	for _, e := range entries {
		fmt.Printf("%v\n", e)
		if e.Interface != nil {
			fmt.Printf("%v\n", *e.Interface)
		}
	}

	return entries, nil
}

// inet_ntoa converts a uint32 to net.IP.
func inet_ntoa(n uint32) net.IP {
	var bytes [4]byte
	bytes[0] = byte(n & 0xFF)
	bytes[1] = byte((n >> 8) & 0xFF)
	bytes[2] = byte((n >> 16) & 0xFF)
	bytes[3] = byte((n >> 24) & 0xFF)

	return net.IPv4(bytes[3], bytes[2], bytes[1], bytes[0])
}

var (
	modiphlpapi = syscall.NewLazyDLL("iphlpapi.dll")

	procGetIpNetTable    = modiphlpapi.NewProc("GetIpNetTable")
	procDeleteIpNetEntry = modiphlpapi.NewProc("DeleteIpNetEntry")
	procSendARP          = modiphlpapi.NewProc("SendARP")
)

type ipNetTable struct {
	NumEntries uint32
	Table      []*ipNetRow
}

// UnmarshalBinary unmarshals a binary buffer into the struct.
func (t *ipNetTable) UnmarshalBinary(b []byte) error {
	// Unmarshal number of entries.
	sz := int(unsafe.Sizeof(t.NumEntries))
	numEntries := binary.LittleEndian.Uint32(b[0:sz])
	t.NumEntries = uint32(numEntries)
	// Unmarshal the entries.
	sizeofIpNetRow := int(unsafe.Sizeof(ipNetRow{}))
	for i := sz; i < len(b); i += sizeofIpNetRow {
		if len(t.Table) == int(numEntries) {
			break
		}

		row := &ipNetRow{}
		if err := row.UnmarshalBinary(b[i : i+sizeofIpNetRow]); err != nil {
			return err
		}

		t.Table = append(t.Table, row)
	}

	return nil
}

type ipNetRow struct {
	Index       uint32
	PhysAddrLen uint32
	PhysAddr    [8]byte
	Addr        uint32
	Type        uint32
}

// UnmarshalBinary unmarshals a binary buffer into the struct.
func (r *ipNetRow) UnmarshalBinary(b []byte) error {
	// Unmarshal adapter index.
	sz := int(unsafe.Sizeof(r.Index))
	idx := binary.LittleEndian.Uint32(b[0:sz])
	b = b[sz:]
	r.Index = uint32(idx)
	// Unmarshal physical address length.
	sz = int(unsafe.Sizeof(r.PhysAddrLen))
	physAddrLen := binary.LittleEndian.Uint32(b[0:sz])
	b = b[sz:]
	r.PhysAddrLen = uint32(physAddrLen)
	// Unmarshal physical address.
	sz = int(unsafe.Sizeof(r.PhysAddr))
	copy(r.PhysAddr[:], b[0:sz])
	b = b[sz:]
	// Unmarshal address.
	sz = int(unsafe.Sizeof(r.Addr))
	addr := binary.LittleEndian.Uint32(b[0:sz])
	b = b[sz:]
	r.Addr = uint32(addr)
	// Unmarshal address.
	sz = int(unsafe.Sizeof(r.Type))
	typ := binary.LittleEndian.Uint32(b[0:sz])
	b = b[sz:]
	r.Type = uint32(typ)

	return nil
}

//func getIpNetTable(nt *ipNetTable, size *uint32, order bool) (err error) {
func getIpNetTable(nt []byte, size *uint32, order bool) (err error) {
	var _p0 uint32 = 0
	if order {
		_p0 = 1
	}

	if nt == nil {
		nt = make([]byte, 1)
		*size = 0
	}
	r0, _, _ := syscall.Syscall(procGetIpNetTable.Addr(), 3, uintptr(unsafe.Pointer(&nt[0])), uintptr(unsafe.Pointer(size)), uintptr(_p0))
	if r0 != 0 {
		err = syscall.Errno(r0)
	}
	return
}
