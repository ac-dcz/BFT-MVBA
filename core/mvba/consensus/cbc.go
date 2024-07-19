package consensus

import (
	"bft/mvba/core"
	"bft/mvba/crypto"
	"sync"
	"sync/atomic"
)

type CBCBack struct {
	Epoch      int64
	Author     core.NodeID
	Tag        uint8
	Commitment []bool
}

const (
	DATA_CBC   uint8 = 0
	COMMIT_CBC uint8 = 1
)

type CBC struct {
	c             *Core
	Proposer      core.NodeID
	Epoch         int64
	BMutex        sync.Mutex
	BlockHash     *crypto.Digest
	Commitment    []bool
	unHandleMutex sync.Mutex
	unHandleReady []*Ready
	unHandleFinal []*Final
	readyCnts     atomic.Int32
	finalCnts     atomic.Int32
	cbcCallBack   chan *CBCBack
}

func NewCBC(c *Core, Proposer core.NodeID, Epoch int64, cbcCallBack chan *CBCBack) *CBC {
	cbc := &CBC{
		c:             c,
		Proposer:      Proposer,
		Epoch:         Epoch,
		BMutex:        sync.Mutex{},
		BlockHash:     nil,
		Commitment:    nil,
		unHandleMutex: sync.Mutex{},
		unHandleReady: nil,
		unHandleFinal: nil,
		readyCnts:     atomic.Int32{},
		finalCnts:     atomic.Int32{},
		cbcCallBack:   cbcCallBack,
	}

	return cbc
}

func (instance *CBC) ProcessProposal(p *Proposal) {
	if p.Author != instance.Proposer {
		return
	}
	instance.BMutex.Lock()
	d := p.B.Hash()
	instance.BlockHash = &d
	instance.BMutex.Unlock()

	instance.unHandleMutex.Lock()
	for _, ready := range instance.unHandleReady {
		go instance.ProcessReady(ready)
	}
	for _, final := range instance.unHandleFinal {
		go instance.ProcessFinal(final)
	}
	instance.unHandleReady, instance.unHandleFinal = nil, nil
	instance.unHandleMutex.Unlock()

	//make vote
	ready, _ := NewReady(instance.c.Name, instance.Proposer, instance.Epoch, DATA_CBC, instance.c.SigService)

	if instance.c.Name == instance.Proposer {
		instance.c.Transimtor.RecvChannel() <- ready
	} else {
		instance.c.Transimtor.Send(instance.c.Name, instance.Proposer, ready)
	}

}

func (instance *CBC) ProcessCommitment(c *Commitment) {
	if c.Author != instance.Proposer {
		return
	}
	instance.BMutex.Lock()
	instance.Commitment = c.C
	instance.BMutex.Unlock()

	instance.unHandleMutex.Lock()
	for _, ready := range instance.unHandleReady {
		go instance.ProcessReady(ready)
	}
	for _, final := range instance.unHandleFinal {
		go instance.ProcessFinal(final)
	}
	instance.unHandleReady, instance.unHandleFinal = nil, nil
	instance.unHandleMutex.Unlock()

	//make vote
	ready, _ := NewReady(instance.c.Name, instance.Proposer, instance.Epoch, COMMIT_CBC, instance.c.SigService)

	if instance.c.Name == instance.Proposer {
		instance.c.Transimtor.RecvChannel() <- ready
	} else {
		instance.c.Transimtor.Send(instance.c.Name, instance.Proposer, ready)
	}
}

func (instance *CBC) ProcessReady(r *Ready) {
	instance.BMutex.Lock()
	flag := false
	if r.Tag == DATA_CBC {
		if instance.BlockHash == nil {
			flag = true
		}
	} else if r.Tag == COMMIT_CBC {
		if instance.Commitment == nil {
			flag = true
		}
	}
	if flag {
		instance.BMutex.Unlock()
		instance.unHandleMutex.Lock()
		instance.unHandleReady = append(instance.unHandleReady, r)
		instance.unHandleMutex.Unlock()
		return
	}
	instance.BMutex.Unlock()

	cnts := instance.readyCnts.Add(1)
	if int(cnts) == instance.c.Committee.HightThreshold() {
		//make final
		final, _ := NewFinal(instance.c.Name, instance.Epoch, r.Tag, instance.c.SigService)
		instance.c.Transimtor.Send(instance.c.Name, core.NONE, final)
		instance.c.Transimtor.RecvChannel() <- final
	}
}

func (instance *CBC) ProcessFinal(f *Final) {
	instance.BMutex.Lock()
	flag := false
	if f.Tag == DATA_CBC {
		if instance.BlockHash == nil {
			flag = true
		}
	} else if f.Tag == COMMIT_CBC {
		if instance.Commitment == nil {
			flag = true
		}
	}
	if flag {
		instance.BMutex.Unlock()
		instance.unHandleMutex.Lock()
		instance.unHandleFinal = append(instance.unHandleFinal, f)
		instance.unHandleMutex.Unlock()
		return
	}
	instance.BMutex.Unlock()

	cnts := instance.finalCnts.Add(1)
	if int(cnts) == 1 {
		//notify core
		instance.cbcCallBack <- &CBCBack{
			Epoch:      instance.Epoch,
			Author:     instance.Proposer,
			Tag:        f.Tag,
			Commitment: instance.Commitment,
		}
	}
}
