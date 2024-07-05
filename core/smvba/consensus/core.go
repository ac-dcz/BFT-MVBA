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

	FinishFlags  map[int64]map[int64]map[core.NodeID]crypto.Digest // finish? map[epoch][round][node] = blockHash
	SPbInstances map[int64]map[int64]map[core.NodeID]*SPB          // map[epoch][node][round]
	DoneFlags    map[int64]map[int64]struct{}
	ReadyFlags   map[int64]map[int64]struct{}
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
		FinishFlags:  make(map[int64]map[int64]map[core.NodeID]crypto.Digest),
		SPbInstances: make(map[int64]map[int64]map[core.NodeID]*SPB),
		DoneFlags:    make(map[int64]map[int64]struct{}),
		ReadyFlags:   make(map[int64]map[int64]struct{}),
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

/*********************************** Protocol Start***************************************/
func (c *Core) handleSpbProposal(p *SPBProposal) error {
	logger.Debug.Printf("Processing SPBProposal epoch %d round %d phase %d\n", p.Epoch, p.Round, p.Phase)

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
	} else if flag == 1 {
		return c.invokeDoneAndShare(d.Epoch, d.Round)
	} else if flag == 2 {
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
				halt, _ := NewHalt(c.Name, leader, d, epoch, c.SigService)
				c.Transimtor.Send(c.Name, core.NONE, halt)
				c.Transimtor.RecvChannel() <- halt
			} else {
				//send preVote
				var preVote *Prevote
				if spb := c.getSpbInstance(epoch, round, leader); spb.IsLock() {
					preVote, _ = NewPrevote(c.Name, epoch, round, VOTE_FLAG_YES, c.SigService)
				} else {
					preVote, _ = NewPrevote(c.Name, epoch, round, VOTE_FLAG_NO, c.SigService)
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

	return nil
}

func (c *Core) handleFinvote(fv *FinVote) error {
	logger.Debug.Printf("Processing FinVote epoch %d round %d\n", fv.Epoch, fv.Round)

	//discard message
	if c.messgaeFilter(fv.Epoch) {
		return nil
	}

	return nil
}

func (c *Core) handleHalt(h *Halt) error {
	logger.Debug.Printf("Processing Halt epoch %d\n", h.Epoch)

	//discard message
	if c.messgaeFilter(h.Epoch) {
		return nil
	}
	return nil
}

/*********************************** Protocol End***************************************/
func (c *Core) Run() {
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
