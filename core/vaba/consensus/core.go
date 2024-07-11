package consensus

import (
	"bft/mvba/core"
	"bft/mvba/crypto"
	"bft/mvba/logger"
	"bft/mvba/pool"
	"bft/mvba/store"
	"sync"
)

type Core struct {
	Name           core.NodeID
	Committee      core.Committee
	Parameters     core.Parameters
	SigService     *crypto.SigService
	Store          *store.Store
	TxPool         *pool.Pool
	Transimtor     *core.Transmitor
	Commitor       *Committor
	Aggreator      *Aggreator
	Elector        *Elector
	Epoch          int64
	Lock           int64
	PBInstances    map[int64]map[core.NodeID]*Promote
	mSkip          sync.Mutex
	SkipFlag       map[int64]struct{}
	electFlag      map[int64]struct{}
	viewChangeFlag map[int64]struct{}
	viewChangeCnts map[int64]int
	commitFlag     map[int64]struct{}
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
		Name:           Name,
		Epoch:          0,
		Lock:           0,
		Committee:      Committee,
		Parameters:     Parameters,
		SigService:     SigService,
		Store:          Store,
		TxPool:         TxPool,
		Transimtor:     Transimtor,
		Commitor:       NewCommittor(callBack),
		Aggreator:      NewAggreator(Committee),
		Elector:        NewElector(SigService, Committee),
		PBInstances:    make(map[int64]map[core.NodeID]*Promote),
		SkipFlag:       make(map[int64]struct{}),
		electFlag:      make(map[int64]struct{}),
		viewChangeFlag: make(map[int64]struct{}),
		viewChangeCnts: make(map[int64]int),
		commitFlag:     make(map[int64]struct{}),
	}

	return c
}

func (c *Core) StoreBlock(block *Block) error {
	key := block.Hash()
	val, err := block.Encode()
	if err != nil {
		return err
	}
	return c.Store.Write(key[:], val)
}

func (c *Core) GetBlock(hash crypto.Digest) (*Block, error) {
	data, err := c.Store.Read(hash[:])

	if err == store.ErrNotFoundKey {
		logger.Error.Println("not key")
		return nil, nil
	}

	if err != nil {
		logger.Error.Println("error")
		return nil, err
	}

	block := &Block{}
	if err := block.Decode(data); err != nil {
		logger.Error.Println("decode error")
		return nil, err
	}
	return block, nil
}

func (c *Core) GetPBInstance(epoch int64, node core.NodeID) *Promote {
	items, ok := c.PBInstances[epoch]
	if !ok {
		items = make(map[core.NodeID]*Promote)
		c.PBInstances[epoch] = items
	}
	item, ok := items[node]
	if !ok {
		item = NewPromote(c, epoch, node)
		items[node] = item
	}
	return item
}

func (c *Core) messageFilter(epoch int64) bool {
	//do something
	return epoch < c.Epoch
}

func (c *Core) setSkip(epoch int64) {
	c.mSkip.Lock()
	defer c.mSkip.Unlock()
	c.SkipFlag[epoch] = struct{}{}
}

func (c *Core) isSkip(epoch int64) bool {
	c.mSkip.Lock()
	defer c.mSkip.Unlock()
	_, ok := c.SkipFlag[epoch]
	return ok
}

func (c *Core) generatorBlock(epoch int64) *Block {
	block := NewBlock(c.Name, c.TxPool.GetBatch(), epoch)
	if len(block.Batch.Txs) > 0 {
		logger.Info.Printf("create Block epoch %d node %d batch_id %d \n", block.Epoch, block.Proposer, block.Batch.ID)
	}
	return block
}

/*******************************Protocol***********************************/

func (c *Core) handleProposal(p *Proposal) error {
	logger.Debug.Printf("processing proposal epoch %d phase %d proposer %d\n", p.Epoch, p.Phase, p.Author)

	//Ensure all Block
	if p.Phase == PHASE_ONE_FALG {
		if _, ok := c.commitFlag[p.Epoch]; ok {
			if c.Elector.Leader(p.Epoch) == p.Author {
				c.Commitor.Commit(p.B)
			}
		}
	}

	if c.messageFilter(p.Epoch) {
		return nil
	}
	if p.Phase == PHASE_ONE_FALG {
		if err := c.StoreBlock(p.B); err != nil {
			return err
		}
		if p.Epoch < c.Lock {
			return nil
		}
	}

	go c.GetPBInstance(p.Epoch, p.Author).processProposal(p)

	return nil
}

func (c *Core) handleVote(v *Vote) error {
	logger.Debug.Printf("processing vote epoch %d phase %d proposer %d\n", v.Epoch, v.Phase, v.Proposer)
	if c.messageFilter(v.Epoch) {
		return nil
	}

	go c.GetPBInstance(v.Epoch, v.Proposer).processVote(v)

	return nil
}

func (c *Core) handleDone(d *Done) error {
	logger.Debug.Printf("processing done epoch %d\n", d.Epoch)
	if c.messageFilter(d.Epoch) {
		return nil
	}

	if ok, err := c.Aggreator.addDoneVote(d); err != nil {
		return err
	} else if ok {
		share, _ := NewSkipShare(c.Name, d.Epoch, c.SigService)
		c.Transimtor.Send(c.Name, core.NONE, share)
		c.Transimtor.RecvChannel() <- share
	}

	return nil
}

func (c *Core) handleSkipShare(s *SkipShare) error {
	logger.Debug.Printf("processing skip share epoch %d\n", s.Epoch)
	if c.messageFilter(s.Epoch) {
		return nil
	}

	if ok, err := c.Aggreator.addSkipVote(s); err != nil {
		return err
	} else if ok {
		c.setSkip(s.Epoch)
		skip, _ := NewSkip(c.Name, s.Epoch, c.SigService)
		c.Transimtor.Send(c.Name, core.NONE, skip)
		return c.invokeElect(s.Epoch)
	}

	return nil
}

func (c *Core) handleSkip(s *Skip) error {
	logger.Debug.Printf("processing skip epoch %d\n", s.Epoch)
	if c.messageFilter(s.Epoch) {
		return nil
	}
	if !c.isSkip(s.Epoch) {
		c.setSkip(s.Epoch)
		temp, _ := NewSkip(c.Name, s.Epoch, c.SigService)
		c.Transimtor.Send(c.Name, core.NONE, temp)
		return c.invokeElect(s.Epoch)
	}
	return nil
}

func (c *Core) invokeElect(epoch int64) error {
	logger.Debug.Printf("Processing invoke elect epoch %d \n", epoch)
	if _, ok := c.electFlag[epoch]; !ok {
		c.electFlag[epoch] = struct{}{}
		elect, _ := NewElectShare(c.Name, epoch, c.SigService)
		c.Transimtor.Send(c.Name, core.NONE, elect)
		c.Transimtor.RecvChannel() <- elect
	}
	return nil
}

func (c *Core) handleElectShare(e *ElectShare) error {
	logger.Debug.Printf("processing electShare epoch %d\n", e.Epoch)
	if c.messageFilter(e.Epoch) {
		return nil
	}

	if leader, err := c.Elector.AddShareVote(e); err != nil {
		return err
	} else if leader != core.NONE {
		return c.invokeViewChange(e.Epoch, leader)
	}

	return nil
}

func (c *Core) invokeViewChange(epoch int64, leader core.NodeID) error {
	logger.Debug.Println("processing invoke view change epoch", epoch, "Leader", leader)
	if _, ok := c.viewChangeFlag[epoch]; !ok {
		c.viewChangeFlag[epoch] = struct{}{}
		if c.Elector.Leader(epoch) == core.NONE {
			c.Elector.SetLeader(epoch, leader)
		}
		pb := c.GetPBInstance(epoch, leader)
		viewChange, _ := NewViewChange(c.Name, leader, epoch, pb.BlockHash(), pb.IsCommit(), pb.IsLock(), pb.IsKey(), c.SigService)
		c.Transimtor.Send(c.Name, core.NONE, viewChange)
		c.Transimtor.RecvChannel() <- viewChange
	}
	return nil
}

func (c *Core) handleViewChange(v *ViewChange) error {
	logger.Debug.Printf("processing ViewChange epoch %d \n", v.Epoch)
	if c.messageFilter(v.Epoch) {
		return nil
	}
	if _, ok := c.commitFlag[v.Epoch]; ok {
		return nil
	}

	c.viewChangeCnts[v.Epoch]++
	if v.IsCommit {
		if block, err := c.GetBlock(*v.BlockHash); err == nil && block != nil {
			block.Epoch = v.Epoch
			c.Commitor.Commit(block)
		}
		c.commitFlag[v.Epoch] = struct{}{}
		halt, _ := NewHalt(c.Name, v.Leader, *v.BlockHash, v.Epoch, c.SigService)
		c.Transimtor.Send(c.Name, core.NONE, halt)
		c.advanceNextEpoch(v.Epoch+1, nil)
	}
	if v.IsLock && v.Epoch >= c.Lock {
		c.Lock = v.Epoch
	}

	if _, ok := c.commitFlag[v.Epoch]; !ok { //may be commit
		if c.viewChangeCnts[v.Epoch] == c.Committee.HightThreshold() { //2f+1?
			c.commitFlag[v.Epoch] = struct{}{}
			c.Commitor.Commit(&Block{Epoch: v.Epoch, Batch: pool.Batch{}})
			c.advanceNextEpoch(v.Epoch+1, v.BlockHash)
		}
	}

	return nil
}

func (c *Core) handleHalt(halt *Halt) error {
	logger.Debug.Printf("processing halt message epoch %d\n", halt.Epoch)

	if c.messageFilter(halt.Epoch) {
		return nil
	}
	if _, ok := c.commitFlag[halt.Epoch]; ok {
		return nil
	}

	if block, err := c.GetBlock(halt.BlockHash); err == nil && block != nil {
		block.Epoch = halt.Epoch
		c.Commitor.Commit(block)
	}
	c.commitFlag[halt.Epoch] = struct{}{}
	temp, _ := NewHalt(c.Name, halt.Leader, halt.BlockHash, halt.Epoch, c.SigService)
	c.Transimtor.Send(c.Name, core.NONE, temp)
	c.advanceNextEpoch(halt.Epoch+1, nil)

	return nil
}

/*******************************Protocol***********************************/
func (c *Core) advanceNextEpoch(epoch int64, blockHash *crypto.Digest) error {
	logger.Debug.Println("advance next epoch ", epoch)
	if epoch <= c.Epoch {
		return nil
	}
	c.Epoch = epoch
	var proposal *Proposal
	if blockHash == nil {
		block := c.generatorBlock(epoch)
		proposal, _ = NewProposal(c.Name, epoch, PHASE_ONE_FALG, block, c.SigService)
	} else {
		if block, err := c.GetBlock(*blockHash); err != nil {
			return err
		} else if block != nil {
			proposal, _ = NewProposal(c.Name, epoch, PHASE_ONE_FALG, block, c.SigService)
		} else {
			proposal, _ = NewProposal(c.Name, epoch, PHASE_ONE_FALG, c.generatorBlock(epoch), c.SigService)
		}
	}
	c.Transimtor.Send(c.Name, core.NONE, proposal)
	c.Transimtor.RecvChannel() <- proposal
	return nil
}

func (c *Core) Run() {

	proposal, _ := NewProposal(c.Name, c.Epoch, PHASE_ONE_FALG, c.generatorBlock(c.Epoch), c.SigService)
	if err := c.Transimtor.Send(c.Name, core.NONE, proposal); err != nil {
		panic("first proposal " + err.Error())
	}
	c.Transimtor.RecvChannel() <- proposal
	var recvChannel = c.Transimtor.RecvChannel()

	for {
		var err error
		select {

		case msg := <-recvChannel:

			{
				if v, ok := msg.(Validator); ok {
					if !v.Verify(c.Committee) {
						err = core.ErrSignature(msg.MsgType())
						break
					}
				}

				switch msg.MsgType() {

				case ProposalType:
					err = c.handleProposal(msg.(*Proposal))
				case VoteType:
					err = c.handleVote(msg.(*Vote))
				case DoneType:
					err = c.handleDone(msg.(*Done))
				case SkipShareType:
					err = c.handleSkipShare(msg.(*SkipShare))
				case SkipType:
					err = c.handleSkip(msg.(*Skip))
				case ElectShareType:
					err = c.handleElectShare(msg.(*ElectShare))
				case ViewChangeType:
					err = c.handleViewChange(msg.(*ViewChange))
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
