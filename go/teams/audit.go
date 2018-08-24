package teams

import (
	"fmt"
	lru "github.com/hashicorp/golang-lru"
	"github.com/keybase/client/go/libkb"
	"github.com/keybase/client/go/protocol/keybase1"
	"sync"
	"time"
)

type AuditParams struct {
	RootFreshness         time.Duration
	MerkleMovementTrigger keybase1.Seqno
	NumPreProbes          int
}

var params = AuditParams{
	RootFreshness:         time.Minute,
	MerkleMovementTrigger: keybase1.Seqno(1000),
	NumPreProbes:          25,
}

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
func (a *Auditor) AuditTeam(m libkb.MetaContext, id keybase1.TeamID, isPublic bool, headMerkle keybase1.MerkleRootV2, chain map[keybase1.Seqno]keybase1.LinkID, maxSeqno keybase1.Seqno) (err error) {

	m = m.WithLogTag("AUDIT")
	defer m.CTrace(fmt.Sprintf("Auditor#AuditTeam(%+v)", id), func() error { return err })()

	if id.IsPublic() != isPublic {
		return NewBadPublicError(id, isPublic)
	}

	// Single-flight lock by team ID.
	lock := a.locktab.AcquireOnName(m.Ctx(), m.G(), id.String())
	defer lock.Release(m.Ctx())

	return a.auditLocked(m, id, headMerkle, chain, maxSeqno)
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

func (a *Auditor) checkRecent(m libkb.MetaContext, history *keybase1.AuditHistory, root *libkb.MerkleRoot) bool {
	if root == nil {
		m.CDebugf("no recent known merkle root in checkRecent")
		return false
	}
	last := lastAudit(history)
	if last == nil {
		m.CDebugf("no recent audits")
		return false
	}
	diff := *root.Seqno() - last.MaxMerkleSeqno
	if diff >= params.MerkleMovementTrigger {
		m.CDebugf("previous merkle audit was %v ago", diff)
		return false
	}
	return true
}

func lastAudit(h *keybase1.AuditHistory) *keybase1.Audit {
	if h == nil {
		return nil
	}
	if len(h.Audits) == 0 {
		return nil
	}
	ret := h.Audits[len(h.Audits)-1]
	return &ret
}

func makeHistory(history *keybase1.AuditHistory, id keybase1.TeamID) *keybase1.AuditHistory {
	if history == nil {
		return &keybase1.AuditHistory{
			ID:         id,
			Public:     id.IsPublic(),
			PreProbes:  make(map[keybase1.Seqno]int),
			PostProbes: make(map[keybase1.Seqno]int),
		}
	}
	ret := history.DeepCopy()
	return &ret
}

func (a *Auditor) doPreProbes(m libkb.MetaContext, history *keybase1.AuditHistory, probeId int, headMerkle keybase1.MerkleRootV2) (err error) {
	first := m.G().MerkleClient.FirstSeqnoWithSkips()
	if first == nil {
		return NewAuditError("cannot find a first modern merkle sequence")
	}

	return a.doProbes(m, history.PreProbes, probeId, *first, headMerkle.Seqno, params.NumPreProbes)
}

func (a *Auditor) doProbes(m libkb.MetaContext, probes map[keybase1.Seqno]int, probeId int, left keybase1.Seqno, right keybase1.Seqno, n int) (err error) {
	for len(probes) < n {

	}
	return nil
}

func (a *Auditor) auditLocked(m libkb.MetaContext, id keybase1.TeamID, headMerkle keybase1.MerkleRootV2, chain map[keybase1.Seqno]keybase1.LinkID, maxChainSeqno keybase1.Seqno) (err error) {

	defer m.CTrace(fmt.Sprintf("Auditor#auditLocked(%v)", id), func() error { return err })()

	lru := a.getLRU()

	history, err := a.getFromCache(m, id, lru)
	if err != nil {
		return err
	}

	last := lastAudit(history)
	if last != nil && last.MaxChainSeqno == maxChainSeqno {
		m.CDebugf("Short-circuit audit, since there is no new data (@%v)", maxChainSeqno)
		return nil
	}

	root, err := m.G().MerkleClient.FetchRootFromServerByFreshness(m, params.RootFreshness)
	if err != nil {
		return err
	}

	if history != nil && a.checkRecent(m, history, root) {
		m.CDebugf("cached audit was recent; short-circuiting")
		return nil
	}

	history = makeHistory(history, id)

	newAuditIndex := len(history.Audits)

	err = a.doPreProbes(m, history, newAuditIndex, headMerkle)
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
