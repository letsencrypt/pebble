package db

import (
	"fmt"
	"sync"

	"github.com/letsencrypt/pebble/core"
)

// Pebble keeps all of its various objects (registrations, orders, etc)
// in-memory, not persisted anywhere. MemoryStore implements this in-memory
// "database"
type MemoryStore struct {
	sync.RWMutex

	// Each Registration's ID is the hex encoding of a SHA256 sum over its public
	// key bytes.
	registrationsByID map[string]*core.Registration

	ordersByID map[string]*core.Order

	authorizationsByID map[string]*core.Authorization

	challengesByID map[string]*core.Challenge

	certificatesByID map[string]*core.Certificate
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		registrationsByID:  make(map[string]*core.Registration),
		ordersByID:         make(map[string]*core.Order),
		authorizationsByID: make(map[string]*core.Authorization),
		challengesByID:     make(map[string]*core.Challenge),
		certificatesByID:   make(map[string]*core.Certificate),
	}
}

func (m *MemoryStore) GetRegistrationByID(id string) *core.Registration {
	m.RLock()
	defer m.RUnlock()
	if reg, present := m.registrationsByID[id]; present {
		return reg
	}
	return nil
}

func (m *MemoryStore) AddRegistration(reg *core.Registration) (int, error) {
	m.Lock()
	defer m.Unlock()

	regID := reg.ID
	if len(regID) == 0 {
		return 0, fmt.Errorf("registration must have a non-empty ID to add to MemoryStore")
	}

	if reg.Key == nil {
		return 0, fmt.Errorf("registration must not have a nil Key")
	}

	if _, present := m.registrationsByID[regID]; present {
		return 0, fmt.Errorf("registration %q already exists", regID)
	}

	m.registrationsByID[regID] = reg
	return len(m.registrationsByID), nil
}

func (m *MemoryStore) AddOrder(order *core.Order) (int, error) {
	m.Lock()
	defer m.Unlock()

	orderID := order.ID
	if len(orderID) == 0 {
		return 0, fmt.Errorf("order must have a non-empty ID to add to MemoryStore")
	}

	if _, present := m.ordersByID[orderID]; present {
		return 0, fmt.Errorf("order %q already exists", orderID)
	}

	m.ordersByID[orderID] = order
	return len(m.ordersByID), nil
}

func (m *MemoryStore) GetOrderByID(id string) *core.Order {
	m.RLock()
	defer m.RUnlock()
	if order, present := m.ordersByID[id]; present {
		return order
	}
	return nil
}

func (m *MemoryStore) AddAuthorization(authz *core.Authorization) (int, error) {
	m.Lock()
	defer m.Unlock()

	authzID := authz.ID
	if len(authzID) == 0 {
		return 0, fmt.Errorf("authz must have a non-empty ID to add to MemoryStore")
	}

	if _, present := m.authorizationsByID[authzID]; present {
		return 0, fmt.Errorf("authz %q already exists", authzID)
	}

	m.authorizationsByID[authzID] = authz
	return len(m.authorizationsByID), nil
}

func (m *MemoryStore) GetAuthorizationByID(id string) *core.Authorization {
	m.RLock()
	defer m.RUnlock()
	if authz, present := m.authorizationsByID[id]; present {
		return authz
	}
	return nil
}

func (m *MemoryStore) AddChallenge(chal *core.Challenge) (int, error) {
	m.Lock()
	defer m.Unlock()

	chalID := chal.ID
	if len(chalID) == 0 {
		return 0, fmt.Errorf("challenge must have a non-empty ID to add to MemoryStore")
	}

	if _, present := m.challengesByID[chalID]; present {
		return 0, fmt.Errorf("challenge %q already exists", chalID)
	}

	m.challengesByID[chalID] = chal
	return len(m.challengesByID), nil
}

func (m *MemoryStore) GetChallengeByID(id string) *core.Challenge {
	m.RLock()
	defer m.RUnlock()
	if chal, present := m.challengesByID[id]; present {
		return chal
	}
	return nil
}

func (m *MemoryStore) AddCertificate(cert *core.Certificate) (int, error) {
	m.Lock()
	defer m.Unlock()

	certID := cert.ID
	if len(certID) == 0 {
		return 0, fmt.Errorf("cert must have a non-empty ID to add to MemoryStore")
	}

	if _, present := m.certificatesByID[certID]; present {
		return 0, fmt.Errorf("cert %q already exists", certID)
	}

	m.certificatesByID[certID] = cert
	return len(m.certificatesByID), nil
}

func (m *MemoryStore) GetCertificateByID(id string) *core.Certificate {
	m.RLock()
	defer m.RUnlock()
	if cert, present := m.certificatesByID[id]; present {
		return cert
	}
	return nil
}
