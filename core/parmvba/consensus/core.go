package consensus

import (
	"bft/mvba/core"
	"bft/mvba/crypto"
	"bft/mvba/logger"
	"bft/mvba/pool"
	"bft/mvba/store"
)

type Core struct {
	Name       core.NodeID
	Committee  core.Committee
	Parameters core.Parameters
	SigService *crypto.SigService
	Store      *store.Store
	TxPool     *pool.Pool
	Transimtor *core.Transmitor
	Aggreator  *Aggreator
	Elector    *Elector
	Commitor   *Committor

	FinishFlags  map[int64]map[int64]map[core.NodeID]crypto.Digest // finish? map[epoch][round][node] = blockHash
	SPbInstances map[int64]map[int64]map[core.NodeID]*SPB          // map[epoch][node][round]
	DoneFlags    map[int64]map[int64]struct{}
	ReadyFlags   map[int64]map[int64]struct{}
	HaltFlags    map[int64]struct{}
	Epoch        int64
}

func NewCore(
	Name core.NodeID,
	Committee core.Committee,
	Parameters core.Parameters,
	SigService *crypto.SigService,
	Store *store.Store,
	TxPool *pool.Pool,
	Transimtor *core.Transmitor,
	callBack chan<- struct{},
) *Core {

	c := &Core{
		Name:         Name,
		Committee:    Committee,
		Parameters:   Parameters,
		SigService:   SigService,
		Store:        Store,
		TxPool:       TxPool,
		Transimtor:   Transimtor,
		Epoch:        0,
		Aggreator:    NewAggreator(Committee),
		Elector:      NewElector(SigService, Committee),
		Commitor:     NewCommittor(callBack, Store),
		FinishFlags:  make(map[int64]map[int64]map[core.NodeID]crypto.Digest),
		SPbInstances: make(map[int64]map[int64]map[core.NodeID]*SPB),
		DoneFlags:    make(map[int64]map[int64]struct{}),
		ReadyFlags:   make(map[int64]map[int64]struct{}),
		HaltFlags:    make(map[int64]struct{}),
	}

	return c
}

func (c *Core) messgaeFilter(epoch int64) bool {
	return epoch < c.Epoch
}

func (c *Core) storeBlock(block *Block) error {
	key := block.Hash()
	value, err := block.Encode()
	if err != nil {
		return err
	}
	return c.Store.Write(key[:], value)
}

func (c *Core) getBlock(digest crypto.Digest) (*Block, error) {
	value, err := c.Store.Read(digest[:])

	if err == store.ErrNotFoundKey {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	b := &Block{}
	if err := b.Decode(value); err != nil {
		return nil, err
	}
	return b, err
}

func (c *Core) getSpbInstance(epoch, round int64, node core.NodeID) *SPB {
	rItems, ok := c.SPbInstances[epoch]
	if !ok {
		rItems = make(map[int64]map[core.NodeID]*SPB)
		c.SPbInstances[epoch] = rItems
	}
	instances, ok := rItems[round]
	if !ok {
		instances = make(map[core.NodeID]*SPB)
		rItems[round] = instances
	}
	instance := NewSPB(c, epoch, round, node)
	instances[node] = instance

	return instance
}

func (c *Core) hasFinish(epoch, round int64, node core.NodeID) (bool, crypto.Digest) {
	if items, ok := c.FinishFlags[epoch]; !ok {
		return false, crypto.Digest{}
	} else {
		if item, ok := items[round]; !ok {
			return false, crypto.Digest{}
		} else {
			d, ok := item[node]
			return ok, d
		}
	}
}

func (c *Core) hasReady(epoch, round int64) bool {
	if items, ok := c.ReadyFlags[epoch]; !ok {
		return false
	} else {
		_, ok = items[round]
		return ok
	}
}

func (c *Core) getReference(epoch, round int64) []crypto.Digest {
	var reference []crypto.Digest
	for i := 0; i < c.Committee.Size(); i++ {
		if ok, d := c.hasFinish(epoch, round, core.NodeID(i)); ok {
			reference = append(reference, d)
		}
	}
	return reference
}

func (c *Core) generatorBlock(epoch int64, reference []crypto.Digest) *Block {
	block := NewBlock(c.Name, c.TxPool.GetBatch(), epoch, reference)
	if len(block.Batch.Txs) > 0 {
		logger.Info.Printf("create Block epoch %d node %d batch_id %d \n", block.Epoch, block.Proposer, block.Batch.ID)
	}
	return block
}

/*********************************** Protocol Start***************************************/
func (c *Core) handleSpbProposal(p *SPBProposal) error {
	logger.Debug.Printf("Processing SPBProposal epoch %d round %d phase %d\n", p.Epoch, p.Round, p.Phase)

	//ensure all block is received
	if p.Phase == SPB_ONE_PHASE {
		if _, ok := c.HaltFlags[p.Epoch]; ok {
			if leader := c.Elector.Leader(p.Epoch, p.Round); leader == p.Author {
				c.Commitor.Commit(p.B)
			}
		}
	}

	//discard message
	if c.messgaeFilter(p.Epoch) {
		return nil
	}

	//Store Block at first time
	if p.Phase == SPB_ONE_PHASE {
		if err := c.storeBlock(p.B); err != nil {
			logger.Error.Printf("Store Block error: %v\n", err)
			return err
		}
	}

	spb := c.getSpbInstance(p.Epoch, p.Round, p.Author)
	go spb.processProposal(p)

	return nil
}

func (c *Core) handleSpbVote(v *SPBVote) error {
	logger.Debug.Printf("Processing SPBVote epoch %d round %d phase %d\n", v.Epoch, v.Round, v.Phase)

	//discard message
	if c.messgaeFilter(v.Epoch) {
		return nil
	}

	spb := c.getSpbInstance(v.Epoch, v.Round, v.Proposer)
	go spb.processVote(v)

	return nil
}

func (c *Core) handleFinish(f *Finish) error {
	logger.Debug.Printf("Processing Finish epoch %d round %d\n", f.Epoch, f.Round)

	//discard message
	if c.messgaeFilter(f.Epoch) {
		return nil
	}
	if ok, err := c.Aggreator.AddFinishVote(f); err != nil {
		return err
	} else if !ok {
		rF, ok := c.FinishFlags[f.Epoch]
		if !ok {
			rF = make(map[int64]map[core.NodeID]crypto.Digest)
		}
		nF, ok := rF[f.Round]
		if !ok {
			nF = make(map[core.NodeID]crypto.Digest)
		}
		nF[f.Author] = f.BlockHash
	} else {
		return c.invokeDoneAndShare(f.Epoch, f.Round)
	}

	return nil
}

func (c *Core) invokeDoneAndShare(epoch, round int64) error {
	logger.Debug.Printf("Processing invoke Done and Share epoch %d,roubd %d\n", epoch, round)

	if _, ok := c.DoneFlags[epoch][round]; !ok {

		done, _ := NewDone(c.Name, epoch, round, c.SigService)
		share, _ := NewElectShare(c.Name, epoch, round, c.SigService)

		c.Transimtor.Send(c.Name, core.NONE, done)
		c.Transimtor.Send(c.Name, core.NONE, share)
		c.Transimtor.RecvChannel() <- done
		c.Transimtor.RecvChannel() <- share

		c.DoneFlags[epoch][round] = struct{}{}
	}

	return nil
}

func (c *Core) handleDone(d *Done) error {
	logger.Debug.Printf("Processing Done epoch %d round %d\n", d.Epoch, d.Round)

	//discard message
	if c.messgaeFilter(d.Epoch) {
		return nil
	}

	if flag, err := c.Aggreator.AddDoneVote(d); err != nil {
		return err
	} else if flag == DONE_LOW_FLAG {
		return c.invokeDoneAndShare(d.Epoch, d.Round)
	} else if flag == DONE_HIGH_FLAG {
		items, ok := c.ReadyFlags[d.Epoch]
		if !ok {
			items = make(map[int64]struct{})
			c.ReadyFlags[d.Epoch] = items
		}
		items[d.Round] = struct{}{}
		return c.processLeader(d.Epoch, d.Round)
	}

	return nil
}

func (c *Core) handleElectShare(share *ElectShare) error {
	logger.Debug.Printf("Processing ElectShare epoch %d round %d\n", share.Epoch, share.Round)

	//discard message
	if c.messgaeFilter(share.Epoch) {
		return nil
	}

	if leader, err := c.Elector.AddShareVote(share); err != nil {
		return err
	} else if leader != core.NONE {
		c.processLeader(share.Epoch, share.Round)
	}

	return nil
}

func (c *Core) processLeader(epoch, round int64) error {

	if c.hasReady(epoch, round) {
		if leader := c.Elector.Leader(epoch, round); leader != core.NONE {
			if ok, d := c.hasFinish(epoch, round, leader); ok {
				//send halt
				halt, _ := NewHalt(c.Name, leader, d, epoch, round, c.SigService)
				c.Transimtor.Send(c.Name, core.NONE, halt)
				c.Transimtor.RecvChannel() <- halt
			} else {
				//send preVote
				var preVote *Prevote
				if spb := c.getSpbInstance(epoch, round, leader); spb.IsLock() {
					if blockHash, ok := spb.GetBlockHash().(crypto.Digest); !ok {
						panic("block hash is nil")
					} else {
						preVote, _ = NewPrevote(c.Name, leader, epoch, round, VOTE_FLAG_YES, blockHash, c.SigService)
					}
				} else {
					preVote, _ = NewPrevote(c.Name, leader, epoch, round, VOTE_FLAG_NO, crypto.Digest{}, c.SigService)
				}
				c.Transimtor.Send(c.Name, core.NONE, preVote)
				c.Transimtor.RecvChannel() <- preVote
			}
		}
	}

	return nil
}

func (c *Core) handlePrevote(pv *Prevote) error {
	logger.Debug.Printf("Processing Prevote epoch %d round %d\n", pv.Epoch, pv.Round)

	//discard message
	if c.messgaeFilter(pv.Epoch) {
		return nil
	}

	if flag, err := c.Aggreator.AddPreVote(pv); err != nil {
		return err
	} else if flag == ACTION_NO {
		vote, _ := NewFinVote(c.Name, pv.Leader, pv.Epoch, pv.Round, VOTE_FLAG_NO, pv.BlockHash, c.SigService)
		c.Transimtor.Send(c.Name, core.NONE, vote)
		c.Transimtor.RecvChannel() <- vote
	} else if flag == ACTION_YES {
		vote, _ := NewFinVote(c.Name, pv.Leader, pv.Epoch, pv.Round, VOTE_FLAG_YES, pv.BlockHash, c.SigService)
		c.Transimtor.Send(c.Name, core.NONE, vote)
		c.Transimtor.RecvChannel() <- vote
	}

	return nil
}

func (c *Core) handleFinvote(fv *FinVote) error {
	logger.Debug.Printf("Processing FinVote epoch %d round %d\n", fv.Epoch, fv.Round)

	//discard message
	if c.messgaeFilter(fv.Epoch) {
		return nil
	}

	if flag, err := c.Aggreator.AddFinVote(fv); err != nil {
		return err
	} else if flag == ACTION_YES {
		return c.advanceNextRound(fv.Epoch, fv.Round, flag, fv.BlockHash)
	} else if flag == ACTION_NO {
		return c.advanceNextRound(fv.Epoch, fv.Round, flag, crypto.Digest{})
	} else if flag == ACTION_COMMIT {
		halt, _ := NewHalt(c.Name, fv.Leader, fv.BlockHash, fv.Epoch, fv.Round, c.SigService)
		c.Transimtor.Send(c.Name, core.NONE, halt)
		c.Transimtor.RecvChannel() <- halt
	}

	return nil
}

func (c *Core) advanceNextRound(epoch, round int64, flag int8, blockHash crypto.Digest) error {
	//discard message
	if c.messgaeFilter(epoch) {
		return nil
	}
	if flag == ACTION_NO { //next round block self
		if inte := c.getSpbInstance(epoch, round, c.Name).GetBlockHash(); inte != nil {
			blockHash = inte.(crypto.Digest)
		}
	}

	var proposal *SPBProposal
	if block, err := c.getBlock(blockHash); err != nil {
		return err
	} else if block != nil {
		proposal, _ = NewSPBProposal(c.Name, block, epoch, round+1, SPB_ONE_PHASE, c.SigService)
	} else {
		proposal, _ = NewSPBProposal(c.Name, c.generatorBlock(epoch, nil), epoch, round+1, SPB_ONE_PHASE, c.SigService)
	}
	c.Transimtor.Send(c.Name, core.NONE, proposal)
	c.Transimtor.RecvChannel() <- proposal

	return nil
}

func (c *Core) handleHalt(h *Halt) error {
	logger.Debug.Printf("Processing Halt epoch %d\n", h.Epoch)

	//discard message
	if c.messgaeFilter(h.Epoch) {
		return nil
	}

	//Check leader

	if _, ok := c.HaltFlags[h.Epoch]; !ok {
		c.Elector.SetLeader(h.Epoch, h.Round, h.Leader)
		if err := c.handleOutput(h.Epoch, h.BlockHash); err != nil {
			return err
		}
		c.HaltFlags[h.Epoch] = struct{}{}
		c.advanceNextEpoch(h.Epoch+1, c.getReference(h.Epoch, h.Round))
	}

	return nil
}

func (c *Core) handleOutput(epoch int64, blockHash crypto.Digest) error {
	logger.Debug.Printf("Processing Ouput epoch %d \n", epoch)
	if b, err := c.getBlock(blockHash); err != nil {
		if err == store.ErrNotFoundKey {
			// retriever
			logger.Debug.Printf("Processing retriever epoch %d \n", epoch)
		}
		return err
	} else {
		c.Commitor.Commit(b)
	}

	return nil
}

/*********************************** Protocol End***************************************/
func (c *Core) advanceNextEpoch(epoch int64, reference []crypto.Digest) {
	if epoch <= c.Epoch {
		return
	}

	//Clear Something
	c.Epoch = epoch
	block := c.generatorBlock(epoch, reference)
	proposal, _ := NewSPBProposal(c.Name, block, epoch, 0, SPB_ONE_PHASE, c.SigService)
	c.Transimtor.Send(c.Name, core.NONE, proposal)
	c.Transimtor.RecvChannel() <- proposal
}

func (c *Core) Run() {
	//first proposal
	block := c.generatorBlock(c.Epoch, nil)
	proposal, _ := NewSPBProposal(c.Name, block, c.Epoch, 0, SPB_ONE_PHASE, c.SigService)
	if err := c.Transimtor.Send(c.Name, core.NONE, proposal); err != nil {
		panic(err)
	}
	c.Transimtor.RecvChannel() <- proposal

	recvChannal := c.Transimtor.RecvChannel()
	for {
		var err error
		select {
		case msg := <-recvChannal:
			{
				if validator, ok := msg.(Validator); ok {
					if !validator.Verify(c.Committee) {
						err = core.ErrSignature(msg.MsgType())
						break
					}
				}

				switch msg.MsgType() {

				case SPBProposalType:
					err = c.handleSpbProposal(msg.(*SPBProposal))
				case SPBVoteType:
					err = c.handleSpbVote(msg.(*SPBVote))
				case FinishType:
					err = c.handleFinish(msg.(*Finish))
				case DoneType:
					err = c.handleDone(msg.(*Done))
				case ElectShareType:
					err = c.handleElectShare(msg.(*ElectShare))
				case PrevoteType:
					err = c.handlePrevote(msg.(*Prevote))
				case FinVoteType:
					err = c.handleFinvote(msg.(*FinVote))
				case HaltType:
					err = c.handleHalt(msg.(*Halt))

				}
			}
		default:
		}
		if err != nil {
			logger.Warn.Println(err)
		}
	}
}
