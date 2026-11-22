package mapcidr

import (
	"bytes"
	"errors"
	"math/big"
	"net"
	"sort"
	"strconv"
)

// ErrNilNetwork is returned when an operation expects a non-nil network.
var ErrNilNetwork = errors.New("network must not be nil")

// InvalidPrefixLengthError indicates a requested split prefix is outside the
// valid range for the network being split.
type InvalidPrefixLengthError struct {
	Prefix int
	Bits   int
	Min    int
}

func (e *InvalidPrefixLengthError) Error() string {
	return "invalid prefix length " + strconv.Itoa(e.Prefix) +
		": must be between " + strconv.Itoa(e.Min) + " and " + strconv.Itoa(e.Bits)
}

// canonicalIPNet returns a copied, canonicalized network. The IP is masked
// with the network mask and normalized to the 4-byte representation for IPv4
// so that mixed v4/v4-in-v6 inputs and host-bits-set inputs compare
// consistently.
func canonicalIPNet(network *net.IPNet) *net.IPNet {
	if network == nil {
		return nil
	}
	ones, bits := network.Mask.Size()
	mask := net.CIDRMask(ones, bits)
	ip := network.IP.Mask(mask)
	if v4 := ip.To4(); v4 != nil && bits == ipv4BitLen {
		ip = v4
	}
	return &net.IPNet{IP: ip, Mask: mask}
}

// canonicalizeIPNets copies the input networks into canonical form, dropping
// nil entries. The returned slice is safe to reorder without touching the
// caller's data.
func canonicalizeIPNets(networks []*net.IPNet) []*net.IPNet {
	canonical := make([]*net.IPNet, 0, len(networks))
	for _, network := range networks {
		if network == nil {
			continue
		}
		canonical = append(canonical, canonicalIPNet(network))
	}
	return canonical
}

// lessIPNet orders networks by address family (IPv4 before IPv6), then by
// network address, and finally by prefix length (more specific first).
func lessIPNet(a, b *net.IPNet) bool {
	aIsV4, bIsV4 := a.IP.To4() != nil, b.IP.To4() != nil
	if aIsV4 != bIsV4 {
		return aIsV4
	}
	if cmp := bytes.Compare(a.IP, b.IP); cmp != 0 {
		return cmp < 0
	}
	aOnes, _ := a.Mask.Size()
	bOnes, _ := b.Mask.Size()
	return aOnes > bOnes
}

// DedupCIDRs removes duplicate networks from the input while preserving a
// deterministic, ascending order. Networks are treated as equal when they
// cover the same address space, regardless of their textual representation
// (e.g. 10.0.0.1/24 and 10.0.0.0/24 collapse to a single 10.0.0.0/24).
// IPv4 and IPv6 networks are both supported and IPv4 results come first.
func DedupCIDRs(networks []*net.IPNet) []*net.IPNet {
	canonical := canonicalizeIPNets(networks)
	if len(canonical) == 0 {
		return nil
	}

	sort.Slice(canonical, func(i, j int) bool {
		return lessIPNet(canonical[i], canonical[j])
	})

	unique := canonical[:0]
	for _, network := range canonical {
		if len(unique) > 0 {
			last := unique[len(unique)-1]
			if last.IP.Equal(network.IP) && bytes.Equal(last.Mask, network.Mask) {
				continue
			}
		}
		unique = append(unique, network)
	}
	return unique
}

// AggregateCIDRs merges the input networks into the smallest equivalent set
// of CIDRs. Duplicate and nested networks are removed, and adjacent networks
// are combined into their common supernet whenever possible. IPv4 and IPv6
// networks are aggregated independently, with IPv4 results returned first in
// ascending order. The inputs are never modified.
func AggregateCIDRs(networks []*net.IPNet) []*net.IPNet {
	unique := DedupCIDRs(networks)
	if len(unique) == 0 {
		return nil
	}

	type interval struct {
		first *big.Int
		last  *big.Int
		bits  int
	}

	intervals := make([]interval, 0, len(unique))
	for _, network := range unique {
		ones, bits := network.Mask.Size()
		first := new(big.Int).SetBytes(network.IP)
		size := new(big.Int).Lsh(big.NewInt(1), uint(bits-ones))
		last := new(big.Int).Sub(new(big.Int).Add(first, size), big.NewInt(1))
		intervals = append(intervals, interval{first: first, last: last, bits: bits})
	}

	// Sort by address family (IPv4 first) and numeric interval start so the
	// single forward merge below only ever inspects adjacent intervals.
	sort.Slice(intervals, func(i, j int) bool {
		if intervals[i].bits != intervals[j].bits {
			return intervals[i].bits > intervals[j].bits
		}
		return intervals[i].first.Cmp(intervals[j].first) < 0
	})

	merged := make([]interval, 0, len(intervals))
	for _, current := range intervals {
		if len(merged) == 0 || merged[len(merged)-1].bits != current.bits {
			merged = append(merged, current)
			continue
		}
		previous := &merged[len(merged)-1]
		// Overlapping or directly adjacent intervals collapse into one range.
		if current.first.Cmp(new(big.Int).Add(previous.last, big.NewInt(1))) <= 0 {
			if current.last.Cmp(previous.last) > 0 {
				previous.last = current.last
			}
			continue
		}
		merged = append(merged, current)
	}

	aggregated := make([]*net.IPNet, 0, len(merged))
	for _, entry := range merged {
		firstIP := IntegerToIP(entry.first, entry.bits)
		lastIP := IntegerToIP(entry.last, entry.bits)
		cidrs, err := GetCIDRFromIPRange(firstIP, lastIP)
		if err != nil {
			continue
		}
		aggregated = append(aggregated, cidrs...)
	}
	// Normalize ordering: IPv4 before IPv6, then ascending network address.
	// This keeps the output stable regardless of how the interval merge
	// interleaved address families.
	sort.Slice(aggregated, func(i, j int) bool {
		return lessIPNet(aggregated[i], aggregated[j])
	})
	return aggregated
}

// SplitCIDRByPrefix splits a network into all subnets carrying newPrefixLen.
// newPrefixLen must be greater than or equal to the source prefix and fit the
// address family. When newPrefixLen equals the source prefix the source
// network itself is returned.
func SplitCIDRByPrefix(network *net.IPNet, newPrefixLen int) ([]*net.IPNet, error) {
	if network == nil {
		return nil, ErrNilNetwork
	}

	prefixLen, bits := network.Mask.Size()
	if newPrefixLen < prefixLen || newPrefixLen > bits {
		return nil, &InvalidPrefixLengthError{Prefix: newPrefixLen, Bits: bits, Min: prefixLen}
	}

	count := new(big.Int).Lsh(big.NewInt(1), uint(newPrefixLen-prefixLen))
	subnetSize := new(big.Int).Lsh(big.NewInt(1), uint(bits-newPrefixLen))

	base := new(big.Int).SetBytes(canonicalIPNet(network).IP)
	one := big.NewInt(1)
	subnets := make([]*net.IPNet, 0)
	for i := big.NewInt(0); i.Cmp(count) < 0; i.Add(i, one) {
		start := new(big.Int).Add(base, new(big.Int).Mul(i, subnetSize))
		ip := IntegerToIP(start, bits)
		mask := net.CIDRMask(newPrefixLen, bits)
		subnets = append(subnets, &net.IPNet{IP: ip, Mask: mask})
	}
	return subnets, nil
}
