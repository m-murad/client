package teams

import (
	"fmt"
	lru "github.com/hashicorp/golang-lru"
	"github.com/keybase/client/go/libkb"
	"github.com/keybase/client/go/protocol/keybase1"
	"sync"
)

type Auditor struct {

	// single-flight lock on TeamID
	locktab libkb.LockTable

	// Map of TeamID -> AuditHistory
	// The LRU is protected by a mutex, because it's swapped out on logout.
	lruMutex sync.Mutex
	lru      *lru.Cache
}

// ProbabilisticMerkleTeamAudit runs an audit on the links of the given team chain (or subchain).
// The security factor of the audit is a function of the platform type, and the amount of time
// since the last audit. This method should use some sort of long-lived cache (via local DB) so that
// previous audits can be combined with the current one.
func (a *Auditor) AuditTeam(m libkb.MetaContext, id keybase1.TeamID, isPublic bool, headMerkle keybase1.MerkleRootV2, chain map[keybase1.Seqno]keybase1.LinkID) (err error) {

	m = m.WithLogTag("AUDIT")
	defer m.CTrace(fmt.Sprintf("Auditor#AuditTeam(%+v)", id), func() error { return err })()

	if id.IsPublic() != isPublic {
		return NewBadPublicError(id, isPublic)
	}

	// Single-flight lock by team ID.
	lock := a.locktab.AcquireOnName(m.Ctx(), m.G(), id.String())
	defer lock.Release(m.Ctx())

	return a.auditLocked(m, id, headMerkle, chain)
}

func (a *Auditor) getLRU() *lru.Cache {
	a.lruMutex.Lock()
	defer a.lruMutex.Unlock()
	return a.lru
}

func (a *Auditor) getFromLRU(m libkb.MetaContext, id keybase1.TeamID, lru *lru.Cache) *keybase1.AuditHistory {
	tmp, found := lru.Get(id)
	if !found {
		return nil
	}
	ret, ok := tmp.(*keybase1.AuditHistory)
	if !ok {
		m.CErrorf("Bad type assertion in Auditor#getFromLRU")
		return nil
	}
	return ret
}

func (a *Auditor) getFromDisk(m libkb.MetaContext, id keybase1.TeamID) (*keybase1.AuditHistory, error) {
	var ret keybase1.AuditHistory
	found, err := m.G().LocalDb.GetInto(&ret, libkb.DbKey{Typ: libkb.DBTeamAuditor, Key: string(id)})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return &ret, nil
}

func (a *Auditor) getFromCache(m libkb.MetaContext, id keybase1.TeamID, lru *lru.Cache) (*keybase1.AuditHistory, error) {

	ret := a.getFromLRU(m, id, lru)
	if ret != nil {
		return ret, nil
	}
	ret, err := a.getFromDisk(m, id)
	return ret, err
}

func (a *Auditor) putToCache(m libkb.MetaContext, id keybase1.TeamID, lru *lru.Cache, h *keybase1.AuditHistory) (err error) {
	lru.Add(id, h)
	err = m.G().LocalDb.PutObj(libkb.DbKey{Typ: libkb.DBTeamAuditor, Key: string(id)}, nil, *h)
	return err
}

func (a *Auditor) auditLocked(m libkb.MetaContext, id keybase1.TeamID, headMerkle keybase1.MerkleRootV2, chain map[keybase1.Seqno]keybase1.LinkID) (err error) {

	lru := a.getLRU()

	history, err := a.getFromCache(m, id, lru)
	if err != nil {
		return err
	}

	err = a.putToCache(m, id, lru, history)
	if err != nil {
		return err
	}
	return nil
}

func (a *Auditor) newLRU() {

	a.lruMutex.Lock()
	defer a.lruMutex.Unlock()

	if a.lru != nil {
		a.lru.Purge()
	}

	// TODO - make this configurable
	lru, err := lru.New(10000)
	if err != nil {
		panic(err)
	}
	a.lru = lru
}

func (a *Auditor) OnLogout() {
	a.newLRU()
}
