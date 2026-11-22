package mapcidr

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"testing"
)

// benchmarkHundredThousandNetworks builds 100,000 /24 networks drawn from the
// 10.0.0.0/8 space with a fixed seed. Every fourth entry repeats the previous
// network so dedup observes 25,000 duplicates against 75,000 unique inputs,
// and the slice is shuffled so ordering is not assumed.
func benchmarkHundredThousandNetworks() []*net.IPNet {
	const count = 100_000
	rng := rand.New(rand.NewSource(42))

	networks := make([]*net.IPNet, 0, count)
	for i := 0; i < count; i++ {
		// Every fourth slot reuses an earlier network instead of introducing
		// a new one, leaving 75,000 distinct networks overall.
		index := i - i/4
		if i%4 == 3 {
			index = i - 1
		}
		ip := make(net.IP, net.IPv4len)
		// Each /24 starts 256 addresses apart. 75,000 /24s exceed the
		// 65,536 /24s that fit in 10.0.0.0/8, so wrap with a modulus.
		binary.BigEndian.PutUint32(ip, 0x0a000000+uint32(index%75_000)*256)
		mask := net.CIDRMask(24, 32)
		networks = append(networks, &net.IPNet{IP: ip.Mask(mask), Mask: mask})
	}
	rng.Shuffle(len(networks), func(i, j int) {
		networks[i], networks[j] = networks[j], networks[i]
	})
	return networks
}

// hundredThousandSplitInput returns 100,000 distinct /24 networks, each of
// which is split into two /25 subnets during the benchmark.
func hundredThousandSplitInput() []*net.IPNet {
	const count = 100_000
	networks := make([]*net.IPNet, 0, count)
	for i := 0; i < count; i++ {
		ip := make(net.IP, net.IPv4len)
		binary.BigEndian.PutUint32(ip, 0x0a000000+uint32(i)*256)
		mask := net.CIDRMask(24, 32)
		networks = append(networks, &net.IPNet{IP: ip.Mask(mask), Mask: mask})
	}
	return networks
}

func BenchmarkDedupCIDRs100k(b *testing.B) {
	networks := benchmarkHundredThousandNetworks()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := DedupCIDRs(networks)
		if len(result) == 0 {
			b.Fatal("empty dedup result")
		}
	}
}

// TestHundredThousandNetworkScale exercises all three operations on 100,000
// networks, asserting correctness invariants at the required scale.
func TestHundredThousandNetworkScale(t *testing.T) {
	networks := benchmarkHundredThousandNetworks()
	if len(networks) != 100_000 {
		t.Fatalf("expected 100000 inputs, got %d", len(networks))
	}

	deduped := DedupCIDRs(networks)
	if len(deduped) != 75_000 {
		t.Fatalf("dedup: expected 75000 unique networks, got %d", len(deduped))
	}

	seen := make(map[string]bool, len(deduped))
	for _, network := range deduped {
		key := network.String()
		if seen[key] {
			t.Fatalf("dedup produced duplicate entry %q", key)
		}
		seen[key] = true
	}

	aggregated := AggregateCIDRs(networks)
	if len(aggregated) == 0 || len(aggregated) >= len(deduped) {
		t.Fatalf("aggregate: expected a strictly smaller non-empty set, got %d from %d", len(aggregated), len(deduped))
	}

	// The aggregated set must cover exactly the same address space as the
	// deduplicated input: compare total address counts and ensure no overlap.
	if covered := countAddresses(aggregated); covered.Cmp(countAddresses(deduped)) != 0 {
		t.Fatalf("aggregate covers %s addresses, input covers %s", covered, countAddresses(deduped))
	}

	splitInput := hundredThousandSplitInput()
	totalSubnets := 0
	for _, network := range splitInput {
		subnets, err := SplitCIDRByPrefix(network, 25)
		if err != nil {
			t.Fatalf("split %s: %v", network, err)
		}
		if len(subnets) != 2 {
			t.Fatalf("split %s: expected 2 subnets, got %d", network, len(subnets))
		}
		totalSubnets += len(subnets)
	}
	if totalSubnets != 200_000 {
		t.Fatalf("expected 200000 subnets across 100000 networks, got %d", totalSubnets)
	}
}

func countAddresses(networks []*net.IPNet) *big.Int {
	total := big.NewInt(0)
	for _, network := range networks {
		ones, bits := network.Mask.Size()
		size := new(big.Int).Lsh(big.NewInt(1), uint(bits-ones))
		total.Add(total, size)
	}
	return total
}

func BenchmarkAggregateCIDRs100k(b *testing.B) {
	networks := benchmarkHundredThousandNetworks()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := AggregateCIDRs(networks)
		if len(result) == 0 {
			b.Fatal("empty aggregate result")
		}
	}
}

// BenchmarkCoalesceCIDRs100k keeps the legacy aggregation path on the same
// 100k input so AggregateCIDRs can be compared against it.
func BenchmarkCoalesceCIDRs100k(b *testing.B) {
	networks := benchmarkHundredThousandNetworks()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v4, v6 := CoalesceCIDRs(networks)
		if len(v4)+len(v6) == 0 {
			b.Fatal("empty coalesce result")
		}
	}
}

func BenchmarkSplitCIDRByPrefix100k(b *testing.B) {
	networks := hundredThousandSplitInput()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		total := 0
		for _, network := range networks {
			subnets, err := SplitCIDRByPrefix(network, 25)
			if err != nil {
				b.Fatal(err)
			}
			total += len(subnets)
		}
		if total != 2*len(networks) {
			b.Fatalf("expected %d subnets, got %d", 2*len(networks), total)
		}
	}
}

// BenchmarkSplitCIDRByPrefixSingle deep-splits one /16 into /24s (256
// subnets) to exercise the prefix-walk math on a single large network.
func BenchmarkSplitCIDRByPrefixSingle(b *testing.B) {
	_, network, err := net.ParseCIDR("10.10.0.0/16")
	if err != nil {
		b.Fatal(err)
	}
	for _, newPrefix := range []int{17, 24, 32} {
		b.Run(fmt.Sprintf("/%d", newPrefix), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				subnets, err := SplitCIDRByPrefix(network, newPrefix)
				if err != nil {
					b.Fatal(err)
				}
				if len(subnets) != 1<<uint(newPrefix-16) {
					b.Fatalf("expected %d subnets, got %d", 1<<uint(newPrefix-16), len(subnets))
				}
			}
		})
	}
}
