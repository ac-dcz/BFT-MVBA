package consensus

import (
	"bft/mvba/core"
	"bft/mvba/crypto"
	"bft/mvba/logger"
	"sync"
	"sync/atomic"
)

type SPB struct {
	c         *Core
	Proposer  core.NodeID
	Epoch     int64
	Round     int64
	BlockHash atomic.Value

	vm    sync.Mutex
	Votes map[int8]int

	uvm              sync.Mutex
	unHandleVote     []*SPBVote
	unHandleProposal []*SPBProposal

	LockFlag atomic.Bool
}

func NewSPB(c *Core, epoch, round int64, proposer core.NodeID) *SPB {
	return &SPB{
		c:            c,
		Epoch:        epoch,
		Round:        round,
		Proposer:     proposer,
		unHandleVote: make([]*SPBVote, 0),
		Votes:        make(map[int8]int),
	}
}

func (s *SPB) processProposal(p *SPBProposal) {
	if p.Phase == SPB_ONE_PHASE {
		// already recieve
		if s.BlockHash.Load() != nil || s.Proposer != p.B.Proposer {
			return
		}
		blockHash := p.B.Hash()
		s.BlockHash.Store(blockHash)

		if vote, err := NewSPBVote(s.c.Name, p.Author, blockHash, s.Epoch, s.Round, p.Phase, s.c.SigService); err != nil {
			logger.Error.Printf("create spb vote message error:%v \n", err)
		} else {
			if s.c.Name != s.Proposer {
				s.c.Transimtor.Send(s.c.Name, s.Proposer, vote)
			} else {
				s.c.Transimtor.RecvChannel() <- vote
			}
		}

		s.uvm.Lock()
		for _, proposal := range s.unHandleProposal {
			go s.processProposal(proposal)
		}
		for _, vote := range s.unHandleVote {
			go s.processVote(vote)
		}
		s.unHandleProposal = nil
		s.unHandleVote = nil
		s.uvm.Unlock()

	} else if p.Phase == SPB_TWO_PHASE {
		if s.BlockHash.Load() == nil {
			s.uvm.Lock()
			defer s.uvm.Unlock()
			s.unHandleProposal = append(s.unHandleProposal, p)
			return
		}
		//if lock ensure SPB_ONE_PHASE has received
		s.LockFlag.Store(true)
		if vote, err := NewSPBVote(s.c.Name, p.Author, crypto.Digest{}, s.Epoch, s.Round, p.Phase, s.c.SigService); err != nil {
			logger.Error.Printf("create spb vote message error:%v \n", err)
		} else {
			if s.c.Name != s.Proposer {
				s.c.Transimtor.Send(s.c.Name, s.Proposer, vote)
			} else {
				s.c.Transimtor.RecvChannel() <- vote
			}
		}
	}
}

func (s *SPB) processVote(p *SPBVote) {
	if s.BlockHash.Load() == nil {
		s.uvm.Lock()
		s.unHandleVote = append(s.unHandleVote, p)
		s.uvm.Unlock()
		return
	}
	s.vm.Lock()
	s.Votes[p.Phase]++
	num := s.Votes[p.Phase]
	s.vm.Unlock()
	// 2f+1?
	if num == s.c.Committee.HightThreshold() {
		if p.Phase == SPB_ONE_PHASE {
			if proposal, err := NewSPBProposal(
				s.c.Name,
				nil,
				s.Epoch,
				s.Round,
				SPB_TWO_PHASE,
				s.c.SigService,
			); err != nil {
				logger.Error.Printf("create spb proposal message error:%v \n", err)
			} else {
				s.c.Transimtor.Send(s.c.Name, core.NONE, proposal)
				s.c.Transimtor.RecvChannel() <- proposal
			}
		} else if p.Phase == SPB_TWO_PHASE {
			blockHash := s.BlockHash.Load().(crypto.Digest)
			if finish, err := NewFinish(s.c.Name, blockHash, s.Epoch, s.Round, s.c.SigService); err != nil {
				logger.Error.Printf("create finish message error:%v \n", err)
			} else {
				s.c.Transimtor.Send(s.c.Name, core.NONE, finish)
				s.c.Transimtor.RecvChannel() <- finish
			}
		}
	}
}

func (s *SPB) IsLock() bool {
	return s.LockFlag.Load()
}

func (s *SPB) GetBlockHash() any {
	return s.BlockHash.Load()
}
