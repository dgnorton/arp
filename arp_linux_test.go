package arp

import (
	"errors"
	"io/ioutil"
	"net"
	"os"
	"testing"
)

// Test parseCacheFile function happy path.
func TestParseCacheFile(t *testing.T) {
	t.Parallel()

	// Create temporary directory to write license file to.
	d := tempDir()
	defer os.RemoveAll(d)

	// Create a temporary file to write key / vals to.
	filename := tempFile(d, "TestReadWrite_")
	os.Remove(filename)

	// Write a good ARP cache file.
	data := []byte(`IP address       HW type     Flags       HW address            Mask     Device
192.168.0.1      0x1         0x2         14:cf:e2:fd:68:c1     *        wlan0
192.168.0.28     0x1         0x2         00:30:1b:a0:70:c2     *        eth0`)
	panicIfError(ioutil.WriteFile(filename, data, 0666))

	// Test reading good ARP cache file.
	cache, err := parseCacheFile(filename, interfaces)
	if err != nil {
		t.Fatal(err)
	} else if len(cache) != 2 {
		t.Fatalf("\n\texp = %d\n\tgot = %d\n", 2, len(cache))
	} else if cache[0].IP.String() != "192.168.0.1" {
		t.Fatalf("\n\texp = %s\n\tgot = %s\n", "192.168.0.1", cache[0].IP.String())
	} else if cache[0].HardwareAddr.String() != "14:cf:e2:fd:68:c1" {
		t.Fatalf("\n\texp = %s\n\tgot = %s\n", "14:cf:e2:fd:68:c1", cache[0].HardwareAddr.String())
	} else if cache[0].Interface.Name != "wlan0" {
		t.Fatalf("\n\texp = %s\n\tgot = %s\n", "wlan0", cache[0].Interface.Name)
	} else if cache[1].IP.String() != "192.168.0.28" {
		t.Fatalf("\n\texp = %s\n\tgot = %s\n", "192.168.0.28", cache[1].IP.String())
	} else if cache[1].HardwareAddr.String() != "00:30:1b:a0:70:c2" {
		t.Fatalf("\n\texp = %s\n\tgot = %s\n", "00:30:1b:a0:70:c2", cache[1].HardwareAddr.String())
	} else if cache[1].Interface.Name != "eth0" {
		t.Fatalf("\n\texp = %s\n\tgot = %s\n", "eth0", cache[1].Interface.Name)
	}
}

// Test parseCacheFile function with bad ARP cache files.
func TestParseCacheFile_InvalidARPCacheFile(t *testing.T) {
	t.Parallel()

	// Create temporary directory to write license file to.
	d := tempDir()
	defer os.RemoveAll(d)

	// Create a temporary file to write key / vals to.
	filename := tempFile(d, "TestReadWrite_")
	os.Remove(filename)

	// Write ARP cache with invalid remote IP address.
	data := []byte(`IP address       HW type     Flags       HW address            Mask     Device
192.168.0.1      0x1         0x2         14:cf:e2:fd:68:c1     *        wlan0
192.168.0.     0x1         0x2         00:30:1b:a0:70:c2     *        eth0`)
	panicIfError(ioutil.WriteFile(filename, data, 0666))

	// Test reading bad ARP cache file.
	_, err := parseCacheFile(filename, interfaces)
	if err == nil {
		t.Fatal("expected error parsing invalid IP address")
	}
	os.Remove(filename)

	// Write ARP cache with invalid remote MAC address.
	data = []byte(`IP address       HW type     Flags       HW address            Mask     Device
192.168.0.1      0x1         0x2         14:cf:e2:fd:68:c1     *        wlan0
192.168.0.28     0x1         0x2         :30:1b:a0:70:c2     *        eth0`)
	panicIfError(ioutil.WriteFile(filename, data, 0666))

	// Test reading bad ARP cache file.
	if _, err = parseCacheFile(filename, interfaces); err == nil {
		t.Fatal("expected error parsing invalid MAC address")
	}
	os.Remove(filename)

	// Test when ARP cache file doesn't exist.
	if _, err = parseCacheFile(filename, interfaces); err == nil {
		t.Fatal("expected error when ARP cache file doesn't exist")
	}
}

// Test parseCacheFile function when stdlib net.Interfaces() func returns an error.
func TestParseCacheFile_InterfacesFailes(t *testing.T) {
	t.Parallel()

	// Create temporary directory to write license file to.
	d := tempDir()
	defer os.RemoveAll(d)

	// Create a temporary file to write key / vals to.
	filename := tempFile(d, "TestReadWrite_")

	// Create a mock net.Interfaces() func that always returns an error.
	interfaces := func() ([]net.Interface, error) { return nil, errors.New("error") }

	// Test when net.Interfaces() func returns an error.
	if _, err := parseCacheFile(filename, interfaces); err == nil {
		t.Fatal(err)
	}
}

// interfaces simulates a successful net.Interfaces() call.
func interfaces() ([]net.Interface, error) {
	return []net.Interface{
		{
			Index:        1,
			Name:         "wlan0",
			HardwareAddr: parseMAC("28:b2:bd:48:50:1c"),
		},
		{
			Index:        2,
			Name:         "eth0",
			HardwareAddr: parseMAC("54:ee:75:1f:1b:f1"),
		},
	}, nil
}

// parseMAC parses a MAC address from a string or panics.
func parseMAC(s string) net.HardwareAddr {
	ha, err := net.ParseMAC(s)
	panicIfError(err)
	return ha
}

// tempDir returns a temporary directory or panics.
func tempDir() string {
	d, err := ioutil.TempDir("", "xslic_")
	panicIfError(err)
	return d
}

// tempFile returns a temporary file or panics.
func tempFile(dir, prefix string) string {
	f, err := ioutil.TempFile(dir, prefix)
	panicIfError(err)
	f.Close()
	return f.Name()
}

// panicIfError panics if err != nil.
func panicIfError(err error) {
	if err != nil {
		panic(err)
	}
}
