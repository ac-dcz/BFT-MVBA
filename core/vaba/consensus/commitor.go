package consensus

import "bft/mvba/logger"

type Committor struct {
	Index    int64
	Blocks   map[int64]*Block
	commitCh chan *Block
	callBack chan<- struct{}
}

func NewCommittor(callBack chan<- struct{}) *Committor {
	c := &Committor{
		Index:    0,
		Blocks:   map[int64]*Block{},
		commitCh: make(chan *Block, 100),
		callBack: callBack,
	}
	go c.run()
	return c
}

func (c *Committor) Commit(block *Block) {
	if block.Epoch < c.Index {
		return
	}
	c.Blocks[block.Epoch] = block
	for {
		if b, ok := c.Blocks[c.Index]; ok {
			c.commitCh <- b
			delete(c.Blocks, c.Index)
			c.Index++
		} else {
			break
		}
	}
}

func (c *Committor) run() {
	for block := range c.commitCh {
		if block.Batch.Txs != nil {
			logger.Info.Printf("commit Block epoch %d node %d batch_id %d \n", block.Epoch, block.Proposer, block.Batch.ID)
		}
		c.callBack <- struct{}{}
	}
}
