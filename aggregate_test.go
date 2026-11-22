package mapcidr

import (
	"net"
	"reflect"
	"testing"
)

func mustParseCIDR(t *testing.T, value string) *net.IPNet {
	t.Helper()
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", value, err)
	}
	return network
}

func networkStrings(networks []*net.IPNet) []string {
	result := make([]string, 0, len(networks))
	for _, network := range networks {
		result = append(result, network.String())
	}
	return result
}

func TestDedupCIDRs(t *testing.T) {
	t.Run("removes exact and representation duplicates", func(t *testing.T) {
		input := []*net.IPNet{
			mustParseCIDR(t, "10.0.0.0/24"),
			mustParseCIDR(t, "10.0.0.5/24"), // host bits canonicalize to 10.0.0.0/24
			mustParseCIDR(t, "10.0.0.0/24"),
			mustParseCIDR(t, "192.168.1.0/24"),
		}
		got := networkStrings(DedupCIDRs(input))
		want := []string{"10.0.0.0/24", "192.168.1.0/24"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("keeps distinct prefixes on the same base address", func(t *testing.T) {
		input := []*net.IPNet{
			mustParseCIDR(t, "10.0.0.0/24"),
			mustParseCIDR(t, "10.0.0.0/25"),
			mustParseCIDR(t, "10.0.0.0/24"),
		}
		got := networkStrings(DedupCIDRs(input))
		want := []string{"10.0.0.0/25", "10.0.0.0/24"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("mixed families stay separated with ipv4 first", func(t *testing.T) {
		input := []*net.IPNet{
			mustParseCIDR(t, "2001:db8::/32"),
			mustParseCIDR(t, "2001:db8::/32"),
			mustParseCIDR(t, "10.0.0.0/8"),
		}
		got := networkStrings(DedupCIDRs(input))
		want := []string{"10.0.0.0/8", "2001:db8::/32"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("empty and nil inputs", func(t *testing.T) {
		if got := DedupCIDRs(nil); got != nil {
			t.Fatalf("nil input should return nil, got %v", got)
		}
		input := []*net.IPNet{nil, mustParseCIDR(t, "10.0.0.0/32"), nil}
		if got := networkStrings(DedupCIDRs(input)); len(got) != 1 || got[0] != "10.0.0.0/32" {
			t.Fatalf("unexpected result: %v", got)
		}
	})

	t.Run("input slice is not mutated", func(t *testing.T) {
		input := []*net.IPNet{
			mustParseCIDR(t, "10.0.0.0/24"),
			mustParseCIDR(t, "10.0.0.0/24"),
		}
		_ = DedupCIDRs(input)
		if len(input) != 2 {
			t.Fatalf("input length changed to %d", len(input))
		}
	})
}

func TestAggregateCIDRs(t *testing.T) {
	t.Run("merges adjacent sibling subnets", func(t *testing.T) {
		input := []*net.IPNet{
			mustParseCIDR(t, "10.0.0.0/25"),
			mustParseCIDR(t, "10.0.0.128/25"),
		}
		got := networkStrings(AggregateCIDRs(input))
		want := []string{"10.0.0.0/24"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("drops nested and duplicate networks", func(t *testing.T) {
		input := []*net.IPNet{
			mustParseCIDR(t, "10.0.0.0/24"),
			mustParseCIDR(t, "10.0.0.0/25"),
			mustParseCIDR(t, "10.0.0.128/25"),
			mustParseCIDR(t, "10.0.0.0/24"),
		}
		got := networkStrings(AggregateCIDRs(input))
		want := []string{"10.0.0.0/24"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("keeps non-adjacent ranges apart", func(t *testing.T) {
		input := []*net.IPNet{
			mustParseCIDR(t, "10.0.0.0/24"),
			mustParseCIDR(t, "10.0.2.0/24"),
		}
		got := networkStrings(AggregateCIDRs(input))
		want := []string{"10.0.0.0/24", "10.0.2.0/24"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("covers a gap with the minimal cidr set", func(t *testing.T) {
		input := []*net.IPNet{
			mustParseCIDR(t, "10.0.0.0/25"),
			mustParseCIDR(t, "10.0.0.128/26"),
			mustParseCIDR(t, "10.0.0.192/26"),
			mustParseCIDR(t, "10.0.1.0/24"),
		}
		got := networkStrings(AggregateCIDRs(input))
		// The merged interval is fully contiguous, so its minimal cover is a
		// single /23 rather than the two original /24s.
		want := []string{"10.0.0.0/23"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("keeps a real gap unmerged", func(t *testing.T) {
		input := []*net.IPNet{
			mustParseCIDR(t, "10.0.0.0/25"),
			mustParseCIDR(t, "10.0.0.128/25"),
			mustParseCIDR(t, "10.0.2.0/24"),
		}
		got := networkStrings(AggregateCIDRs(input))
		want := []string{"10.0.0.0/24", "10.0.2.0/24"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("supports ipv6 independently", func(t *testing.T) {
		input := []*net.IPNet{
			mustParseCIDR(t, "2001:db8::/33"),
			mustParseCIDR(t, "2001:db8:8000::/33"),
			mustParseCIDR(t, "2001:db8::/33"),
		}
		got := networkStrings(AggregateCIDRs(input))
		want := []string{"2001:db8::/32"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("mixed families preserve order with ipv4 first", func(t *testing.T) {
		input := []*net.IPNet{
			mustParseCIDR(t, "2001:db8:8000::/33"),
			mustParseCIDR(t, "2001:db8::/33"),
			mustParseCIDR(t, "10.0.0.128/25"),
			mustParseCIDR(t, "10.0.0.0/25"),
		}
		got := networkStrings(AggregateCIDRs(input))
		want := []string{"10.0.0.0/24", "2001:db8::/32"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("empty input", func(t *testing.T) {
		if got := AggregateCIDRs(nil); got != nil {
			t.Fatalf("nil input should return nil, got %v", got)
		}
	})

	t.Run("matches CoalesceCIDRs on overlapping random-style input", func(t *testing.T) {
		input := []*net.IPNet{
			mustParseCIDR(t, "192.168.0.0/24"),
			mustParseCIDR(t, "192.168.1.0/24"),
			mustParseCIDR(t, "192.168.2.0/24"),
			mustParseCIDR(t, "192.168.3.0/24"),
			mustParseCIDR(t, "192.168.0.128/25"),
			mustParseCIDR(t, "10.0.0.0/8"),
		}
		got := networkStrings(AggregateCIDRs(input))
		v4, _ := CoalesceCIDRs(input)
		want := networkStrings(v4)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("AggregateCIDRs %v != CoalesceCIDRs %v", got, want)
		}
	})
}

func TestSplitCIDRByPrefix(t *testing.T) {
	t.Run("splits ipv4 into equal halves", func(t *testing.T) {
		got, err := SplitCIDRByPrefix(mustParseCIDR(t, "192.168.1.0/24"), 25)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"192.168.1.0/25", "192.168.1.128/25"}
		if !reflect.DeepEqual(networkStrings(got), want) {
			t.Fatalf("got %v, want %v", networkStrings(got), want)
		}
	})

	t.Run("splits all the way to host prefixes", func(t *testing.T) {
		got, err := SplitCIDRByPrefix(mustParseCIDR(t, "10.0.0.0/30"), 32)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{
			"10.0.0.0/32", "10.0.0.1/32", "10.0.0.2/32", "10.0.0.3/32",
		}
		if !reflect.DeepEqual(networkStrings(got), want) {
			t.Fatalf("got %v, want %v", networkStrings(got), want)
		}
	})

	t.Run("canonicalizes host bits before splitting", func(t *testing.T) {
		got, err := SplitCIDRByPrefix(mustParseCIDR(t, "192.168.1.7/24"), 25)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"192.168.1.0/25", "192.168.1.128/25"}
		if !reflect.DeepEqual(networkStrings(got), want) {
			t.Fatalf("got %v, want %v", networkStrings(got), want)
		}
	})

	t.Run("same prefix returns the canonical source network", func(t *testing.T) {
		got, err := SplitCIDRByPrefix(mustParseCIDR(t, "172.16.0.0/12"), 12)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"172.16.0.0/12"}
		if !reflect.DeepEqual(networkStrings(got), want) {
			t.Fatalf("got %v, want %v", networkStrings(got), want)
		}
	})

	t.Run("supports ipv6", func(t *testing.T) {
		got, err := SplitCIDRByPrefix(mustParseCIDR(t, "2001:db8::/126"), 128)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 4 {
			t.Fatalf("expected 4 subnets, got %d (%v)", len(got), networkStrings(got))
		}
		want := []string{
			"2001:db8::/128",
			"2001:db8::1/128",
			"2001:db8::2/128",
			"2001:db8::3/128",
		}
		if !reflect.DeepEqual(networkStrings(got), want) {
			t.Fatalf("got %v, want %v", networkStrings(got), want)
		}
	})

	t.Run("rejects smaller and out of range prefixes", func(t *testing.T) {
		if _, err := SplitCIDRByPrefix(mustParseCIDR(t, "10.0.0.0/24"), 23); err == nil {
			t.Fatal("expected error for prefix smaller than source prefix")
		}
		if _, err := SplitCIDRByPrefix(mustParseCIDR(t, "10.0.0.0/24"), 33); err == nil {
			t.Fatal("expected error for prefix beyond address width")
		}
		if _, err := SplitCIDRByPrefix(nil, 25); err != ErrNilNetwork {
			t.Fatalf("expected ErrNilNetwork, got %v", err)
		}
	})
}
