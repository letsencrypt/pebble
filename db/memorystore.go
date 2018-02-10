package db

import (
	"fmt"
	"sync"

	"github.com/letsencrypt/pebble/core"
)

// Pebble keeps all of its various objects (accounts, orders, etc)
// in-memory, not persisted anywhere. MemoryStore implements this in-memory
// "database"
type MemoryStore struct {
	sync.RWMutex

	// Each Accounts's ID is the hex encoding of a SHA256 sum over its public
	// key bytes.
	accountsByID map[string]*core.Account

	ordersByID map[string]*core.Order

	authorizationsByID map[string]*core.Authorization

	challengesByID map[string]*core.Challenge

	certificatesByID map[string]*core.Certificate
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		accountsByID:       make(map[string]*core.Account),
		ordersByID:         make(map[string]*core.Order),
		authorizationsByID: make(map[string]*core.Authorization),
		challengesByID:     make(map[string]*core.Challenge),
		certificatesByID:   make(map[string]*core.Certificate),
	}
}

func (m *MemoryStore) GetAccountByID(id string) *core.Account {
	m.RLock()
	defer m.RUnlock()
	return m.accountsByID[id]
}

func (m *MemoryStore) UpdateAccountByID(id string, acct *core.Account) error {
	m.RLock()
	defer m.RUnlock()
	if m.accountsByID[id] == nil {
		return fmt.Errorf("account with ID %q does not exist", id)
	}
	m.accountsByID[id] = acct
	return nil
}

func (m *MemoryStore) AddAccount(acct *core.Account) (int, error) {
	m.Lock()
	defer m.Unlock()

	acctID := acct.ID
	if len(acctID) == 0 {
		return 0, fmt.Errorf("account must have a non-empty ID to add to MemoryStore")
	}

	if acct.Key == nil {
		return 0, fmt.Errorf("account must not have a nil Key")
	}

	if _, present := m.accountsByID[acctID]; present {
		return 0, fmt.Errorf("account %q already exists", acctID)
	}

	m.accountsByID[acctID] = acct
	return len(m.accountsByID), nil
}

func (m *MemoryStore) AddOrder(order *core.Order) (int, error) {
	m.Lock()
	defer m.Unlock()

	order.RLock()
	orderID := order.ID
	if len(orderID) == 0 {
		return 0, fmt.Errorf("order must have a non-empty ID to add to MemoryStore")
	}
	order.RUnlock()

	if _, present := m.ordersByID[orderID]; present {
		return 0, fmt.Errorf("order %q already exists", orderID)
	}

	m.ordersByID[orderID] = order
	return len(m.ordersByID), nil
}

func (m *MemoryStore) GetOrderByID(id string) *core.Order {
	m.RLock()
	defer m.RUnlock()
	return m.ordersByID[id]
}

func (m *MemoryStore) AddAuthorization(authz *core.Authorization) (int, error) {
	m.Lock()
	defer m.Unlock()

	authz.RLock()
	authzID := authz.ID
	if len(authzID) == 0 {
		return 0, fmt.Errorf("authz must have a non-empty ID to add to MemoryStore")
	}
	authz.RUnlock()

	if _, present := m.authorizationsByID[authzID]; present {
		return 0, fmt.Errorf("authz %q already exists", authzID)
	}

	m.authorizationsByID[authzID] = authz
	return len(m.authorizationsByID), nil
}

func (m *MemoryStore) GetAuthorizationByID(id string) *core.Authorization {
	m.RLock()
	defer m.RUnlock()
	return m.authorizationsByID[id]
}

func (m *MemoryStore) AddChallenge(chal *core.Challenge) (int, error) {
	m.Lock()
	defer m.Unlock()

	chal.RLock()
	chalID := chal.ID
	chal.RUnlock()
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
	return m.challengesByID[id]
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
	return m.certificatesByID[id]
}
