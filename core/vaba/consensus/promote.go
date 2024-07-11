package consensus

import (
	"bft/mvba/core"
	"bft/mvba/crypto"
	"bft/mvba/logger"
	"sync"
	"sync/atomic"
)

type Promote struct {
	C        *Core
	Epoch    int64
	Proposer core.NodeID

	mHash     sync.RWMutex
	blockHash *crypto.Digest

	mUnhandle        sync.Mutex
	unhandleProposal []*Proposal
	unhandleVote     []*Vote
	mVoteCnt         sync.Mutex
	voteCnts         map[int8]int

	keyFlag    atomic.Bool
	lockFlag   atomic.Bool
	commitFlag atomic.Bool
}

func NewPromote(c *Core, epoch int64, proposer core.NodeID) *Promote {

	p := &Promote{
		C:                c,
		Epoch:            epoch,
		Proposer:         proposer,
		unhandleProposal: make([]*Proposal, 0),
		unhandleVote:     make([]*Vote, 0),
		mUnhandle:        sync.Mutex{},
		mHash:            sync.RWMutex{},
		blockHash:        nil,
		mVoteCnt:         sync.Mutex{},
		voteCnts:         make(map[int8]int),
	}

	p.keyFlag.Store(false)
	p.lockFlag.Store(false)
	p.commitFlag.Store(false)

	return p
}

func (p *Promote) processProposal(proposal *Proposal) {

	if proposal.Phase != PHASE_ONE_FALG {
		p.mHash.RLock()
		if p.blockHash == nil {
			p.mHash.RUnlock()

			p.mUnhandle.Lock()
			p.unhandleProposal = append(p.unhandleProposal, proposal)
			p.mUnhandle.Unlock()

			return
		}
		p.mHash.RUnlock()
	}

	var vote *Vote

	switch proposal.Phase {
	case PHASE_ONE_FALG:
		{
			if proposal.Author != p.Proposer {
				logger.Warn.Printf("promote error: the proposer of block is not match\n")
				return
			}
			p.mHash.Lock()
			d := proposal.B.Hash()
			p.blockHash = &d
			p.mHash.Unlock()

			p.mUnhandle.Lock()
			for _, item := range p.unhandleProposal {
				go p.processProposal(item)
			}

			for _, vote := range p.unhandleVote {
				go p.processVote(vote)
			}
			p.mUnhandle.Unlock()

			vote, _ = NewVote(p.C.Name, p.Proposer, d, p.Epoch, PHASE_ONE_FALG, p.C.SigService)
		}
	case PHASE_TWO_FALG:
		{
			p.keyFlag.Store(true)
			vote, _ = NewVote(p.C.Name, p.Proposer, *p.blockHash, p.Epoch, PHASE_TWO_FALG, p.C.SigService)
		}
	case PHASE_THREE_FALG:
		{
			p.lockFlag.Store(true)
			vote, _ = NewVote(p.C.Name, p.Proposer, *p.blockHash, p.Epoch, PHASE_THREE_FALG, p.C.SigService)
		}
	case PHASE_FOUR_FALG:
		{
			p.commitFlag.Store(true)
			vote, _ = NewVote(p.C.Name, p.Proposer, *p.blockHash, p.Epoch, PHASE_FOUR_FALG, p.C.SigService)
		}
	}
	if p.C.Name != p.Proposer {
		p.C.Transimtor.Send(p.C.Name, p.Proposer, vote)
	} else {
		p.C.Transimtor.RecvChannel() <- vote
	}

}

func (p *Promote) processVote(vote *Vote) {
	p.mHash.RLock()
	if p.blockHash == nil {
		p.mHash.RUnlock()

		p.mUnhandle.Lock()
		p.unhandleVote = append(p.unhandleVote, vote)
		p.mUnhandle.Unlock()

		return
	} else if *p.blockHash != vote.BlockHash {
		p.mHash.RUnlock()
		logger.Warn.Printf("promote error: the block hash in vote is invaild\n")
		return
	}
	p.mHash.RUnlock()

	p.mVoteCnt.Lock()
	p.voteCnts[vote.Phase]++
	nums := p.voteCnts[vote.Phase]
	p.mVoteCnt.Unlock()

	if nums == p.C.Committee.HightThreshold() {
		if vote.Phase < PHASE_FOUR_FALG {
			proposal, _ := NewProposal(p.Proposer, p.Epoch, vote.Phase+1, nil, p.C.SigService)
			p.C.Transimtor.Send(p.Proposer, core.NONE, proposal)
			p.C.Transimtor.RecvChannel() <- proposal
		} else {
			if !p.C.isSkip(p.Epoch) {
				done, _ := NewDone(p.Proposer, p.Epoch, p.C.SigService)
				p.C.Transimtor.Send(p.Proposer, core.NONE, done)
				p.C.Transimtor.RecvChannel() <- done
			}
		}
	}
}

func (p *Promote) BlockHash() *crypto.Digest {
	return p.blockHash
}

func (p *Promote) IsKey() bool {
	return p.keyFlag.Load()
}

func (p *Promote) IsLock() bool {
	return p.lockFlag.Load()
}

func (p *Promote) IsCommit() bool {
	return p.commitFlag.Load()
}
