package consensus

import (
	"bft/mvba/core"
	"bft/mvba/crypto"
	"bft/mvba/logger"
	"math/rand"
)

const RANDOM_LEN = 7

type Elector struct {
	committee   core.Committee
	sigService  *crypto.SigService
	seeds       map[int64]int64
	randGen     map[int64]*rand.Rand
	randCnt     map[int64]int
	leaders     map[int64]map[int64]core.NodeID
	used        map[int64]map[core.NodeID]struct{}
	electShares map[int64][]crypto.SignatureShare
}

func NewElector(committee core.Committee, sigService *crypto.SigService) *Elector {
	elector := &Elector{
		committee:   committee,
		sigService:  sigService,
		seeds:       make(map[int64]int64),
		randGen:     make(map[int64]*rand.Rand),
		randCnt:     make(map[int64]int),
		leaders:     make(map[int64]map[int64]core.NodeID),
		used:        make(map[int64]map[core.NodeID]struct{}),
		electShares: make(map[int64][]crypto.SignatureShare),
	}
	return elector
}

func (e *Elector) addElectShare(share *ElectShare) (bool, error) {
	used, ok := e.used[share.Epoch]
	if !ok {
		used = make(map[core.NodeID]struct{})
		e.used[share.Epoch] = used
	}
	shares, ok := e.electShares[share.Epoch]
	if !ok {
		shares = make([]crypto.SignatureShare, 0)
		e.electShares[share.Epoch] = shares
	}

	if _, ok := used[share.Author]; ok {
		return false, core.ErrOneMoreMessage(share.MsgType(), share.Epoch, 0, share.Author)
	}
	shares = append(shares, share.Share)
	e.electShares[share.Epoch] = shares

	if len(shares) == e.committee.HightThreshold() {
		//generate seed
		var seed int64 = 0
		data, err := crypto.CombineIntactTSPartial(shares, e.sigService.ShareKey, share.Hash())
		if err != nil {
			logger.Error.Printf("Combine signature error: %v\n", err)
			return false, err
		}
		for i := 0; i < len(data) && i < RANDOM_LEN; i++ {
			seed = seed<<8 + int64(data[i])
		}
		e.addSeed(share.Epoch, seed)
		return true, nil
	}
	return false, nil
}

func (e *Elector) addSeed(epoch, seed int64) {
	logger.Debug.Printf("Epoch %d seed %d\n", epoch, seed)
	e.seeds[epoch] = seed
	e.randGen[epoch] = rand.New(rand.NewSource(seed))
}

func (e *Elector) addLeader(epoch, round int64, leader core.NodeID) {
	leaders, ok := e.leaders[epoch]
	if !ok {
		leaders = make(map[int64]core.NodeID)
		e.leaders[epoch] = leaders
	}
	leaders[round] = leader
}

func (e *Elector) Leader(epoch, round int64) core.NodeID {
	if gen, ok := e.randGen[epoch]; !ok {
		return core.NONE
	} else {
		cnt := e.randCnt[epoch]
		if round < int64(cnt) {
			return e.leaders[epoch][round]
		}
		for cnt < int(round) {
			leader := gen.Uint64() % uint64(e.committee.Size())
			e.addLeader(epoch, int64(cnt)+1, core.NodeID(leader))
			cnt++
		}
		e.randCnt[epoch] = cnt
		return e.leaders[epoch][round]
	}
}
