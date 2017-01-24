package wfe

import (
	"fmt"
	"sync"

	"github.com/letsencrypt/pebble/acme"
)

// Pebble keeps all of its various objects (registrations, orders, etc)
// in-memory, not persisted anywhere. MemoryStore implements this in-memory
// "database"
type memoryStore struct {
	sync.RWMutex

	// Each Registration's ID is the hex encoding of a SHA256 sum over its public
	// key bytes.
	registrationsByID map[string]*acme.Registration

	ordersByID map[string]*acme.Order
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		registrationsByID: make(map[string]*acme.Registration),
		ordersByID:        make(map[string]*acme.Order),
	}
}

func (m *memoryStore) getRegistrationByID(id string) *acme.Registration {
	m.RLock()
	defer m.RUnlock()
	if reg, present := m.registrationsByID[id]; present {
		return reg
	}
	return nil
}

func (m *memoryStore) countRegistrations() int {
	m.RLock()
	defer m.RUnlock()
	return len(m.registrationsByID)
}

func (m *memoryStore) addRegistration(reg *acme.Registration) (*acme.Registration, error) {
	m.Lock()
	defer m.Unlock()

	regID := reg.ID
	if len(regID) == 0 {
		return nil, fmt.Errorf("registration must have a non-empty ID to add to memoryStore")
	}

	if _, present := m.registrationsByID[regID]; present {
		return nil, fmt.Errorf("registration %q already exists", regID)
	}

	m.registrationsByID[regID] = reg
	return reg, nil
}

func (m *memoryStore) addOrder(order *acme.Order) (*acme.Order, error) {
	m.Lock()
	defer m.Unlock()

	orderID := order.ID
	if len(orderID) == 0 {
		return nil, fmt.Errorf("order must have a non-empty ID to add to memoryStore")
	}

	if _, present := m.ordersByID[orderID]; present {
		return nil, fmt.Errorf("order %q already exists", orderID)
	}

	m.ordersByID[orderID] = order
	return order, nil
}

func (m *memoryStore) getOrderByID(id string) *acme.Order {
	m.RLock()
	defer m.RUnlock()
	if order, present := m.ordersByID[id]; present {
		return order
	}
	return nil
}
