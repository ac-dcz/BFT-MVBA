package consensus

import (
	"bft/mvba/core"
	"bft/mvba/logger"
)

type Commitor struct {
	callBack      chan<- struct{}
	commitLeaders map[int64]core.NodeID
	commitBlocks  map[int64]*Block
	blockChan     chan *Block
	curIndex      int64
}

func NewCommitor(callBack chan<- struct{}) *Commitor {
	c := &Commitor{
		callBack:      callBack,
		commitLeaders: make(map[int64]core.NodeID),
		commitBlocks:  make(map[int64]*Block),
		blockChan:     make(chan *Block, 100),
		curIndex:      0,
	}

	go func() {
		for block := range c.blockChan {
			if block.Batch.Txs != nil {
				logger.Info.Printf("commit Block epoch %d node %d batch_id %d \n", block.Epoch, block.Proposer, block.Batch.ID)
			}
			c.callBack <- struct{}{}
		}
	}()

	return c
}

func (c *Commitor) CommitLeader(epoch int64) core.NodeID {
	leader, ok := c.commitLeaders[epoch]
	if !ok {
		return core.NONE
	}
	return leader
}

func (c *Commitor) Commit(epoch int64, leader core.NodeID, block *Block) {
	if epoch < c.curIndex {
		return
	}
	c.commitLeaders[epoch] = leader
	if block == nil {
		return
	}
	c.commitBlocks[epoch] = block
	for {
		if block, ok := c.commitBlocks[c.curIndex]; ok {
			c.blockChan <- block
			delete(c.commitBlocks, c.curIndex)
			c.curIndex++
		} else {
			break
		}
	}
}
