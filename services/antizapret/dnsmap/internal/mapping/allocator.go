package mapping

import (
	"context"
	"fmt"
	"net"
	"sync"

	"dnsmap/internal/firewall"
)

type Manager struct {
	mu         sync.Mutex
	network    uint32
	mask       uint32
	first      uint32
	last       uint32
	cursor     uint32
	firewall   firewall.Firewall
	realToFake map[uint32]uint32
	used       map[uint32]struct{}
}

func New(prefix string, fw firewall.Firewall) (*Manager, error) {
	ip, network, err := net.ParseCIDR(prefix)
	if err != nil || ip.To4() == nil || network.IP.To4() == nil {
		return nil, fmt.Errorf("invalid IPv4 fake-IP range %q", prefix)
	}
	ones, bits := network.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("fake-IP range must be IPv4: %q", prefix)
	}
	networkValue := ipv4Value(network.IP)
	mask := uint32(network.Mask[0])<<24 | uint32(network.Mask[1])<<16 | uint32(network.Mask[2])<<8 | uint32(network.Mask[3])
	broadcast := networkValue | ^mask
	if ones >= 31 || broadcast <= networkValue+1 {
		return nil, fmt.Errorf("fake-IP range %q has no mapping addresses after reserving the first usable host", prefix)
	}
	return &Manager{
		network:    networkValue,
		mask:       mask,
		first:      networkValue + 1,
		last:       broadcast - 1,
		cursor:     networkValue + 2,
		firewall:   fw,
		realToFake: make(map[uint32]uint32),
		used:       make(map[uint32]struct{}),
	}, nil
}

func (m *Manager) Get(real net.IP) (net.IP, bool) {
	value, ok := ipv4ValueOK(real)
	if !ok {
		return nil, false
	}
	m.mu.Lock()
	fake, ok := m.realToFake[value]
	m.mu.Unlock()
	if !ok {
		return nil, false
	}
	return valueIP(fake), true
}

func (m *Manager) Add(ctx context.Context, real net.IP) (net.IP, error) {
	realValue, ok := ipv4ValueOK(real)
	if !ok {
		return nil, fmt.Errorf("real address is not IPv4")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if fake, exists := m.realToFake[realValue]; exists {
		return valueIP(fake), nil
	}

	fake, ok := m.findFreeLocked()
	if !ok {
		if err := m.firewall.Flush(ctx); err != nil {
			return nil, err
		}
		m.resetLocked()
		fake, ok = m.findFreeLocked()
		if !ok {
			return nil, fmt.Errorf("fake-IP range is exhausted after flush")
		}
	}
	if err := m.firewall.Add(ctx, valueIP(fake), valueIP(realValue)); err != nil {
		m.cursor = fake
		return nil, err
	}
	m.used[fake] = struct{}{}
	m.realToFake[realValue] = fake
	return valueIP(fake), nil
}

func (m *Manager) Restore(real, fake net.IP) error {
	realValue, ok := ipv4ValueOK(real)
	if !ok {
		return fmt.Errorf("restored real address is not IPv4")
	}
	fakeValue, ok := ipv4ValueOK(fake)
	if !ok || !m.isMappingAddress(fakeValue) {
		return fmt.Errorf("restored fake address %s is outside the mapping range", fake)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if current, exists := m.realToFake[realValue]; exists {
		if current != fakeValue {
			return fmt.Errorf("real address %s has conflicting fake addresses", real)
		}
		return nil
	}
	if _, exists := m.used[fakeValue]; exists {
		return fmt.Errorf("fake address %s is already used", fake)
	}
	m.used[fakeValue] = struct{}{}
	m.realToFake[realValue] = fakeValue
	return nil
}

func (m *Manager) Snapshot() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make(map[string]string, len(m.realToFake))
	for real, fake := range m.realToFake {
		result[valueIP(real).String()] = valueIP(fake).String()
	}
	return result
}

func (m *Manager) findFreeLocked() (uint32, bool) {
	span := m.last - m.first + 1
	for checked := uint32(0); checked < span; checked++ {
		candidate := m.cursor
		if candidate > m.last || candidate < m.first+1 {
			candidate = m.first + 1
		}
		m.cursor = candidate + 1
		if _, used := m.used[candidate]; !used {
			return candidate, true
		}
	}
	return 0, false
}

func (m *Manager) resetLocked() {
	m.cursor = m.first + 1
	m.realToFake = make(map[uint32]uint32)
	m.used = make(map[uint32]struct{})
}

func (m *Manager) isMappingAddress(value uint32) bool {
	return value >= m.first+1 && value <= m.last && value&m.mask == m.network
}

func ipv4Value(ip net.IP) uint32 {
	return uint32(ip.To4()[0])<<24 | uint32(ip.To4()[1])<<16 | uint32(ip.To4()[2])<<8 | uint32(ip.To4()[3])
}

func ipv4ValueOK(ip net.IP) (uint32, bool) {
	if ip == nil || ip.To4() == nil {
		return 0, false
	}
	return ipv4Value(ip), true
}

func valueIP(value uint32) net.IP {
	return net.IPv4(byte(value>>24), byte(value>>16), byte(value>>8), byte(value)).To4()
}
