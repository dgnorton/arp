package arp

import (
	"testing"
)

func TestCache(t *testing.T) {
	t.Parallel()

	_, err := Cache()
	if err != nil {
		t.Fatal(err)
	}
}
