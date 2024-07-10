package consensus

import (
	"bft/mvba/logger"
	"bft/mvba/store"
)

type Committor struct {
	Index        int64
	Blocks       map[int64]*Block
	commitCh     chan *Block
	isCommitFlag map[int64]struct{}
	callBack     chan<- struct{}
	store        *store.Store
}

func NewCommittor(callBack chan<- struct{}, store *store.Store) *Committor {
	c := &Committor{
		Index:        0,
		Blocks:       map[int64]*Block{},
		commitCh:     make(chan *Block),
		isCommitFlag: make(map[int64]struct{}),
		callBack:     callBack,
		store:        store,
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
			var blocks []*Block

			for _, d := range b.Reference {
				if val, err := c.store.Read(d[:]); err == nil {
					temp := &Block{}
					if err := temp.Decode(val); err == nil {
						if temp.Batch.Txs != nil {
							if _, ok := c.isCommitFlag[int64(temp.Batch.ID)]; !ok {
								c.isCommitFlag[int64(temp.Batch.ID)] = struct{}{}
								blocks = append(blocks, temp)
							}
						}
					}
				}
			}

			if b.Batch.Txs != nil {
				c.isCommitFlag[int64(b.Batch.ID)] = struct{}{}
				blocks = append(blocks, b)
			}

			for _, block := range blocks {
				c.commitCh <- block
			}
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
