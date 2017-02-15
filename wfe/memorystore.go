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

	authorizationsByID map[string]*acme.Authorization
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		registrationsByID:  make(map[string]*acme.Registration),
		ordersByID:         make(map[string]*acme.Order),
		authorizationsByID: make(map[string]*acme.Authorization),
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

func (m *memoryStore) addRegistration(reg *acme.Registration) (int, error) {
	m.Lock()
	defer m.Unlock()

	regID := reg.ID
	if len(regID) == 0 {
		return 0, fmt.Errorf("registration must have a non-empty ID to add to memoryStore")
	}

	if _, present := m.registrationsByID[regID]; present {
		return 0, fmt.Errorf("registration %q already exists", regID)
	}

	m.registrationsByID[regID] = reg
	return len(m.registrationsByID), nil
}

func (m *memoryStore) addOrder(order *acme.Order) (int, error) {
	m.Lock()
	defer m.Unlock()

	orderID := order.ID
	if len(orderID) == 0 {
		return 0, fmt.Errorf("order must have a non-empty ID to add to memoryStore")
	}

	if _, present := m.ordersByID[orderID]; present {
		return 0, fmt.Errorf("order %q already exists", orderID)
	}

	m.ordersByID[orderID] = order
	return len(m.ordersByID), nil
}

func (m *memoryStore) getOrderByID(id string) *acme.Order {
	m.RLock()
	defer m.RUnlock()
	if order, present := m.ordersByID[id]; present {
		return order
	}
	return nil
}

func (m *memoryStore) addAuthorization(authz *acme.Authorization) (int, error) {
	m.Lock()
	defer m.Unlock()

	authzID := authz.ID
	if len(authzID) == 0 {
		return 0, fmt.Errorf("authz must have a non-empty ID to add to memoryStore")
	}

	if _, present := m.authorizationsByID[authzID]; present {
		return 0, fmt.Errorf("authz %q already exists", authzID)
	}

	m.authorizationsByID[authzID] = authz
	return len(m.authorizationsByID), nil
}

func (m *memoryStore) getAuthorizationByID(id string) *acme.Authorization {
	m.RLock()
	defer m.RUnlock()
	if authz, present := m.authorizationsByID[id]; present {
		return authz
	}
	return nil
}
