package consensus

import (
	"bft/mvba/core"
	"bft/mvba/crypto"
)

type Elector struct {
	leaders         map[int64]core.NodeID
	electAggreators map[int64]*ElectAggreator
	sigService      *crypto.SigService
	committee       core.Committee
}

func NewElector(sigService *crypto.SigService, committee core.Committee) *Elector {
	return &Elector{
		leaders:         make(map[int64]core.NodeID),
		electAggreators: make(map[int64]*ElectAggreator),
		sigService:      sigService,
		committee:       committee,
	}
}

func (e *Elector) SetLeader(epoch int64, leader core.NodeID) {
	e.leaders[epoch] = leader
}

func (e *Elector) Leader(epoch int64) core.NodeID {
	if leader, ok := e.leaders[epoch]; !ok {
		return core.NONE
	} else {
		return leader
	}
}

func (e *Elector) AddShareVote(share *ElectShare) (core.NodeID, error) {
	item, ok := e.electAggreators[share.Epoch]
	if !ok {
		item = NewElectAggreator()
		e.electAggreators[share.Epoch] = item
	}
	node, err := item.Append(e.committee, e.sigService, share)
	if err != nil {
		return core.NONE, nil
	}
	if node != core.NONE {
		e.SetLeader(share.Epoch, node)
	}
	return node, nil
}

const RANDOM_LEN = 3

type ElectAggreator struct {
	shares  []crypto.SignatureShare
	authors map[core.NodeID]struct{}
}

func NewElectAggreator() *ElectAggreator {
	return &ElectAggreator{
		shares:  make([]crypto.SignatureShare, 0),
		authors: make(map[core.NodeID]struct{}),
	}
}

func (e *ElectAggreator) Append(committee core.Committee, sigService *crypto.SigService, elect *ElectShare) (core.NodeID, error) {
	if _, ok := e.authors[elect.Author]; ok {
		return core.NONE, core.ErrOneMoreMessage(elect.MsgType(), elect.Epoch, 0, elect.Author)
	}
	e.authors[elect.Author] = struct{}{}
	e.shares = append(e.shares, elect.SigShare)
	if len(e.shares) == committee.HightThreshold() {
		coin, err := crypto.CombineIntactTSPartial(e.shares, sigService.ShareKey, elect.Hash())
		if err == nil {
			return core.NONE, nil
		}
		var rand int
		for i := 0; i < RANDOM_LEN; i++ {
			if coin[i] > 0 {
				rand = rand<<8 + int(coin[i])
			} else {
				rand = rand<<8 + int(-coin[i])
			}
		}
		return core.NodeID(rand) % core.NodeID(committee.Size()), nil
	}
	return core.NONE, nil
}
