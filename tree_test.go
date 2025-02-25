// Copyright (C) 2015 Alex Sergeyev
// This project is licensed under the terms of the MIT license.
// Read LICENSE file for information for all notices and permissions.

package nradix

import (
	"testing"
)

func TestTree(t *testing.T) {
	tr := New[int](0)
	if tr == nil {
		t.Error("Did not create tree properly")
	}

	err := tr.AddCIDR("1.2.3.0/25", 1)
	if err != nil {
		t.Error(err)
	}

	// Matching defined cidr
	inf, ok, err := tr.FindCIDR("1.2.3.1/25")
	if err != nil {
		t.Error(err)
	}
	if inf != 1 && !ok {
		t.Errorf("Wrong value, expected 1, got %v", inf)
	}

	// Inside defined cidr
	inf, ok, err = tr.FindCIDR("1.2.3.60/32")
	if err != nil {
		t.Error(err)
	}
	if inf != 1 && !ok {
		t.Errorf("Wrong value, expected 1, got %v", inf)
	}
	inf, ok, err = tr.FindCIDR("1.2.3.60")
	if err != nil {
		t.Error(err)
	}
	if inf != 1 && !ok {
		t.Errorf("Wrong value, expected 1, got %v", inf)
	}

	// Outside defined cidr
	inf, ok, err = tr.FindCIDR("1.2.3.160/32")
	if err != nil {
		t.Error(err)
	}
	if ok {
		t.Errorf("Wrong value, expected nil, got %v", inf)
	}
	inf, ok, err = tr.FindCIDR("1.2.3.160")
	if err != nil {
		t.Error(err)
	}
	if ok {
		t.Errorf("Wrong value, expected nil, got %v", inf)
	}

	inf, ok, err = tr.FindCIDR("1.2.3.128/25")
	if err != nil {
		t.Error(err)
	}
	if ok {
		t.Errorf("Wrong value, expected nil, got %v", inf)
	}

	// Covering not defined
	inf, ok, err = tr.FindCIDR("1.2.3.0/24")
	if err != nil {
		t.Error(err)
	}
	if inf != zero[int]() && ok {
		t.Errorf("Wrong value, expected nil, got %v", inf)
	}

	// Covering defined
	err = tr.AddCIDR("1.2.3.0/24", 2)
	if err != nil {
		t.Error(err)
	}
	inf, ok, err = tr.FindCIDR("1.2.3.0/24")
	if err != nil {
		t.Error(err)
	}
	if inf != 2 && !ok {
		t.Errorf("Wrong value, expected 2, got %v", inf)
	}

	inf, ok, err = tr.FindCIDR("1.2.3.160/32")
	if err != nil {
		t.Error(err)
	}
	if inf != 2 && !ok {
		t.Errorf("Wrong value, expected 2, got %v", inf)
	}

	// Hit both covering and internal, should choose most specific
	inf, ok, err = tr.FindCIDR("1.2.3.0/32")
	if err != nil {
		t.Error(err)
	}
	if inf != 1 && !ok {
		t.Errorf("Wrong value, expected 1, got %v", inf)
	}

	// Delete internal
	err = tr.DeleteCIDR("1.2.3.0/25")
	if err != nil {
		t.Error(err)
	}

	// Hit covering with old IP
	inf, ok, err = tr.FindCIDR("1.2.3.0/32")
	if err != nil {
		t.Error(err)
	}
	if inf != 2 && !ok {
		t.Errorf("Wrong value, expected 2, got %v", inf)
	}

	// Add internal back in
	err = tr.AddCIDR("1.2.3.0/25", 1)
	if err != nil {
		t.Error(err)
	}

	// Delete covering
	err = tr.DeleteCIDR("1.2.3.0/24")
	if err != nil {
		t.Error(err)
	}

	// Hit with old IP
	inf, ok, err = tr.FindCIDR("1.2.3.0/32")
	if err != nil {
		t.Error(err)
	}
	if inf != 1 && !ok {
		t.Errorf("Wrong value, expected 1, got %v", inf)
	}

	// Find covering again
	inf, ok, err = tr.FindCIDR("1.2.3.0/24")
	if err != nil {
		t.Error(err)
	}
	if ok {
		t.Errorf("Wrong value, expected nil, got %v", inf)
	}

	// Add covering back in
	err = tr.AddCIDR("1.2.3.0/24", 2)
	if err != nil {
		t.Error(err)
	}
	inf, ok, err = tr.FindCIDR("1.2.3.0/24")
	if err != nil {
		t.Error(err)
	}
	if inf != 2 && !ok {
		t.Errorf("Wrong value, expected 2, got %v", inf)
	}

	// Delete the whole range
	err = tr.DeleteWholeRangeCIDR("1.2.3.0/24")
	if err != nil {
		t.Error(err)
	}
	// should be no value for covering
	inf, ok, err = tr.FindCIDR("1.2.3.0/24")
	if err != nil {
		t.Error(err)
	}
	if ok {
		t.Errorf("Wrong value, expected nil, got %v", inf)
	}
	// should be no value for internal
	inf, ok, err = tr.FindCIDR("1.2.3.0/32")
	if err != nil {
		t.Error(err)
	}
	if ok {
		t.Errorf("Wrong value, expected nil, got %v", inf)
	}
}

func TestSet(t *testing.T) {
	tr := New[int](0)
	if tr == nil {
		t.Error("Did not create tree properly")
	}

	tr.AddCIDR("1.1.1.0/24", 1)
	inf, ok, err := tr.FindCIDR("1.1.1.0")
	if err != nil {
		t.Error(err)
	}
	if inf != 1 && !ok {
		t.Errorf("Wrong value, expected 1, got %v", inf)
	}

	tr.AddCIDR("1.1.1.0/25", 2)
	inf, ok, err = tr.FindCIDR("1.1.1.0")
	if err != nil {
		t.Error(err)
	}
	if inf != 2 && !ok {
		t.Errorf("Wrong value, expected 2, got %v", inf)
	}
	inf, ok, err = tr.FindCIDR("1.1.1.0/24")
	if err != nil {
		t.Error(err)
	}
	if inf != 1 && !ok {
		t.Errorf("Wrong value, expected 1, got %v", inf)
	}

	// add covering should fail
	err = tr.AddCIDR("1.1.1.0/24", 60)
	if err != ErrNodeBusy {
		t.Errorf("Should have gotten ErrNodeBusy, instead got err: %v", err)
	}

	// set covering
	err = tr.SetCIDR("1.1.1.0/24", 3)
	if err != nil {
		t.Error(err)
	}
	inf, ok, err = tr.FindCIDR("1.1.1.0")
	if err != nil {
		t.Error(err)
	}
	if inf != 2 && !ok {
		t.Errorf("Wrong value, expected 2, got %v", inf)
	}
	inf, ok, err = tr.FindCIDR("1.1.1.0/24")
	if err != nil {
		t.Error(err)
	}
	if inf != 3 && !ok {
		t.Errorf("Wrong value, expected 3, got %v", inf)
	}

	// set internal
	err = tr.SetCIDR("1.1.1.0/25", 4)
	if err != nil {
		t.Error(err)
	}
	inf, ok, err = tr.FindCIDR("1.1.1.0")
	if err != nil {
		t.Error(err)
	}
	if inf != 4 && !ok {
		t.Errorf("Wrong value, expected 4, got %v", inf)
	}
	inf, ok, err = tr.FindCIDR("1.1.1.0/24")
	if err != nil {
		t.Error(err)
	}
	if inf != 3 && !ok {
		t.Errorf("Wrong value, expected 3, got %v", inf)
	}
}

func TestRegression(t *testing.T) {
	tr := New[int](0)
	if tr == nil {
		t.Error("Did not create tree properly")
	}

	tr.AddCIDR("1.1.1.0/24", 1)

	tr.DeleteCIDR("1.1.1.0/24")
	tr.AddCIDR("1.1.1.0/25", 2)

	// inside old range, outside new range
	inf, ok, err := tr.FindCIDR("1.1.1.128")
	if err != nil {
		t.Error(err)
	} else if ok {
		t.Errorf("Wrong value, expected nil, got %v", inf)
	}
}

func TestTree6(t *testing.T) {
	tr := New[int](0)
	if tr == nil {
		t.Error("Did not create tree properly")
	}
	err := tr.AddCIDR("dead::0/16", 3)
	if err != nil {
		t.Error(err)
	}

	// Matching defined cidr
	inf, ok, err := tr.FindCIDR("dead::beef")
	if err != nil {
		t.Error(err)
	}
	if inf != 3 && !ok {
		t.Errorf("Wrong value, expected 3, got %v", inf)
	}

	// Outside
	inf, ok, err = tr.FindCIDR("deed::beef/32")
	if err != nil {
		t.Error(err)
	}
	if ok {
		t.Errorf("Wrong value, expected nil, got %v", inf)
	}

	// Subnet
	err = tr.AddCIDR("dead:beef::0/48", 4)
	if err != nil {
		t.Error(err)
	}

	// Match defined subnet
	inf, ok, err = tr.FindCIDR("dead:beef::0a5c:0/64")
	if err != nil {
		t.Error(err)
	}
	if inf != 4 && !ok {
		t.Errorf("Wrong value, expected 4, got %v", inf)
	}

	// Match outside defined subnet
	inf, ok, err = tr.FindCIDR("dead:0::beef:0a5c:0/64")
	if err != nil {
		t.Error(err)
	}
	if inf != 3 && !ok {
		t.Errorf("Wrong value, expected 3, got %v", inf)
	}

}

func TestRegression6(t *testing.T) {
	tr := New[int](0)
	if tr == nil {
		t.Error("Did not create tree properly")
	}
	// in one of the implementations /128 addresses were causing panic...
	tr.AddCIDR("2620:10f::/32", 54321)
	tr.AddCIDR("2620:10f:d000:100::5/128", 12345)

	inf, ok, err := tr.FindCIDR("2620:10f:d000:100::5/128")
	if err != nil {
		t.Errorf("Could not get /128 address from the tree, error: %s", err)
	} else if inf != 12345 && !ok {
		t.Errorf("Wrong value from /128 test, got %d, expected 12345", inf)
	}
}

func TestSingleIpv4MappedIpv6(t *testing.T) {
	tr := New[int](0)

	if err := tr.AddCIDR("::ffff:1.2.3.4", 1); err != nil {
		t.Error("Could not add IPv4-mapped IPv6 address:", err)
	}

	inf, ok, err := tr.FindCIDR("::ffff:1.2.3.4")
	if err != nil {
		t.Error("Could not find IPv4-mapped IPv6 address (::ffff:1.2.3.4), error:", err)
	} else if !ok || inf != 1 {
		t.Error("Found wrong value for IPv4-mapped IPv6 address (::ffff:1.2.3.4):", inf)
	}

	inf, ok, err = tr.FindCIDR("::ffff:0102:0304")
	if err != nil {
		t.Error("Could not find IPv4-mapped IPv6 address (::ffff:0102:0304), error:", err)
	} else if !ok || inf != 1 {
		t.Error("Found wrong value for IPv4-mapped IPv6 address (:::ffff:0102:0304):", inf)
	}

	inf, ok, err = tr.FindCIDR("1.2.3.4")
	if err != nil {
		t.Error("Could not find unmapped IPv4-mapped address (1.2.3.4), error:", err)
	} else if !ok || inf != 1 {
		t.Error("Found wrong value for unmapped IPv4-mapped address (1.2.3.4):", inf)
	}
}

func TestIpv4MappedIpv6Prefix(t *testing.T) {
	tr := New[int](0)

	if err := tr.AddCIDR("::ffff:1.2.0.1/112", 1); err != nil {
		t.Error("Could not add IPv4-mapped IPv6 prefix:", err)
	}

	inf, ok, err := tr.FindCIDR("1.2.3.4")
	if err != nil {
		t.Error("Could not find unmapped IPv4-mapped address (1.2.3.4), error:", err)
	} else if !ok || inf != 1 {
		t.Error("Found wrong value for unmapped IPv4-mapped address (1.2.3.4):", inf)
	}

	inf, ok, err = tr.FindCIDR("1.3.0.0")
	if err != nil {
		t.Error("Could not find unmapped IPv4-mapped address (1.3.0.0), error:", err)
	} else if ok {
		t.Error("Found wrong value for unmapped IPv4-mapped address (1.3.0.0):", inf)
	}
}

func TestInvalidIpv4MappedIpv6Prefix(t *testing.T) {
	tr := New[int](0)

	if err := tr.AddCIDR("::ffff:1.2.3.4/128", 1); err != nil {
		t.Error("Could not add IPv4-mapped IPv6 prefix:", err)
	}

	if err := tr.AddCIDR("::ffff:1.2.3.4/95", 1); err == nil {
		t.Error("Missing error when prefix too small for :", err)
	}
}
