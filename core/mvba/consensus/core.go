package consensus

import (
	"bft/mvba/core"
	"bft/mvba/crypto"
	"bft/mvba/logger"
	"bft/mvba/pool"
	"bft/mvba/store"
	"fmt"
)

type Core struct {
	Name           core.NodeID
	Committee      core.Committee
	Parameters     core.Parameters
	SigService     *crypto.SigService
	Store          *store.Store
	TxPool         *pool.Pool
	Transimtor     *core.Transmitor
	Elector        *Elector
	Aggreator      *Aggreator
	CallBack       chan struct{}
	Epoch          int64
	cbcCallBack    chan *CBCBack
	cbcInstances   map[int64]map[core.NodeID]map[uint8]*CBC //epoch-node-tag
	cbcFinalCnts   map[int64]map[uint8]int                  //epoch-tag finish-cbc cnts
	cbcFinalIndexs map[int64][]bool                         //epoch self-commitment
	commitments    map[int64]map[core.NodeID][]bool         //epoch-node commitment
	abaInstances   map[int64]map[int64]*ABA
}

func NewCore(
	name core.NodeID,
	committee core.Committee,
	parameters core.Parameters,
	SigService *crypto.SigService,
	Store *store.Store,
	TxPool *pool.Pool,
	Transimtor *core.Transmitor,
	CallBack chan struct{},
) *Core {
	core := &Core{
		Name:           name,
		Committee:      committee,
		Parameters:     parameters,
		SigService:     SigService,
		Store:          Store,
		TxPool:         TxPool,
		Transimtor:     Transimtor,
		CallBack:       CallBack,
		Elector:        NewElector(committee, SigService),
		Aggreator:      NewAggreator(committee),
		Epoch:          0,
		cbcCallBack:    make(chan *CBCBack, 1000),
		cbcInstances:   make(map[int64]map[core.NodeID]map[uint8]*CBC),
		cbcFinalCnts:   make(map[int64]map[uint8]int),
		cbcFinalIndexs: make(map[int64][]bool),
		commitments:    make(map[int64]map[core.NodeID][]bool),
	}

	return core
}

func (c *Core) storeBlock(block *Block) error {
	key := block.Hash()
	val, err := block.Encode()
	if err != nil {
		return err
	}
	if err := c.Store.Write(key[:], val); err != nil {
		return err
	}
	return nil
}

func (c *Core) getCBCInstance(epoch int64, node core.NodeID, tag uint8) *CBC {
	items, ok := c.cbcInstances[epoch]
	if !ok {
		items = make(map[core.NodeID]map[uint8]*CBC)
		c.cbcInstances[epoch] = items
	}
	item, ok := items[node]
	if !ok {
		item = make(map[uint8]*CBC)
		items[node] = item
	}
	instance, ok := item[tag]
	if !ok {
		instance = NewCBC(c, node, epoch, c.cbcCallBack)
		item[tag] = instance
	}
	return instance
}

func (c *Core) getABAInstance(epoch, round int64) *ABA {
	items, ok := c.abaInstances[epoch]
	if !ok {
		items = make(map[int64]*ABA)
		c.abaInstances[epoch] = items
	}
	instance, ok := items[round]
	if !ok {
		instance = NewABA(c, epoch, round)
		items[round] = instance
	}
	return instance
}

func (c *Core) addFinals(epoch int64, tag uint8, node core.NodeID) int {
	items, ok := c.cbcFinalCnts[epoch]
	if !ok {
		items = make(map[uint8]int)
		c.cbcFinalCnts[epoch] = items
		c.cbcFinalIndexs[epoch] = make([]bool, c.Committee.Size())
	}

	//record commitment
	if tag == DATA_CBC {
		c.cbcFinalIndexs[epoch][node] = true
	}

	items[tag]++
	cnt := items[tag]
	return cnt
}

func (c *Core) getCommitment(epoch int64, node core.NodeID) []bool {
	items, ok := c.commitments[epoch]
	if !ok {
		return nil
	}
	return items[node]
}

func (c *Core) addCommitment(epoch int64, node core.NodeID, commitment []bool) {
	items, ok := c.commitments[epoch]
	if !ok {
		items = make(map[core.NodeID][]bool)
		c.commitments[epoch] = items
	}
	items[node] = commitment
}

func (c *Core) checkVote(vote *Vote) bool {
	if vote.Flag == FLAG_NO {
		if items, ok := c.commitments[vote.Epoch]; ok {
			if item, ok := items[vote.Author]; ok {
				if item != nil && item[vote.Leader] {
					return true
				}
			}
		}
	}
	return false
}

func (c *Core) messageFilter(epoch int64) bool {
	return c.Epoch > epoch
}

func (c *Core) generateBlock(epoch int64) *Block {
	block := NewBlock(c.Name, c.TxPool.GetBatch(), epoch)
	if block.Batch.Txs != nil {
		logger.Info.Printf("create Block epoch %d node %d batch_id %d \n", block.Epoch, block.Proposer, block.Batch.ID)
	}
	return block
}

/**************************** Protocol ********************************/

func (c *Core) handleProposal(p *Proposal) error {
	logger.Debug.Printf("Processing proposal proposer %d epoch %d\n", p.Author, p.Epoch)
	if c.messageFilter(p.Epoch) {
		return nil
	}

	if err := c.storeBlock(p.B); err != nil {
		return err
	}

	go c.getCBCInstance(p.Epoch, p.Author, DATA_CBC).ProcessProposal(p)

	return nil
}

func (c *Core) handleReady(r *Ready) error {
	logger.Debug.Printf("Processing ready Tag %d epoch %d\n", r.Tag, r.Epoch)
	if c.messageFilter(r.Epoch) {
		return nil
	}
	go c.getCBCInstance(r.Epoch, r.Author, r.Tag).ProcessReady(r)
	return nil
}

func (c *Core) handleFinal(f *Final) error {
	logger.Debug.Printf("Processing final Tag %d epoch %d\n", f.Tag, f.Epoch)
	if c.messageFilter(f.Epoch) {
		return nil
	}
	go c.getCBCInstance(f.Epoch, f.Author, f.Tag).ProcessFinal(f)
	return nil
}

func (c *Core) handleCommitment(commit *Commitment) error {
	logger.Debug.Printf("Processing commitment epoch %d\n", commit.Epoch)
	if c.messageFilter(commit.Epoch) {
		return nil
	}
	go c.getCBCInstance(commit.Epoch, commit.Author, COMMIT_CBC).ProcessCommitment(commit)

	return nil
}

func (c *Core) processCBCBack(back *CBCBack) error {
	logger.Debug.Printf("Processing cbc back tag %d proposer %d epoch %d \n", back.Tag, back.Author, back.Epoch)
	if c.messageFilter(back.Epoch) {
		return nil
	}
	cnt := c.addFinals(back.Epoch, back.Tag, back.Author)
	if back.Tag == COMMIT_CBC {
		c.addCommitment(back.Epoch, back.Author, back.Commitment)
	}

	//wait 2f+1
	if cnt == c.Committee.HightThreshold() {
		if back.Tag == DATA_CBC {
			commitment := c.cbcFinalIndexs[back.Epoch]
			msg, _ := NewCommitment(c.Name, commitment, back.Epoch, c.SigService)
			c.Transimtor.Send(c.Name, core.NONE, msg)
			c.Transimtor.RecvChannel() <- msg
		} else if back.Tag == COMMIT_CBC {
			elect, _ := NewElectShare(c.Name, back.Epoch, c.SigService)
			c.Transimtor.Send(c.Name, core.NONE, elect)
			c.Transimtor.RecvChannel() <- elect
		}
	}
	return nil
}

func (c *Core) handleElectShare(elect *ElectShare) error {
	logger.Debug.Printf("Processing electsahre epoch %d\n", elect.Epoch)
	if c.messageFilter(elect.Epoch) {
		return nil
	}
	if flag, err := c.Elector.addElectShare(elect); err != nil {
		return err
	} else if flag {
		return c.invokeStageTwo(c.Epoch, 0)
	}

	return nil
}

func (c *Core) invokeStageTwo(epoch, round int64) error {
	leader := c.Elector.Leader(epoch, round)
	logger.Debug.Printf("Invoke Stage Two epoch %d round %d leader %d\n", epoch, round, leader)

	commitment := c.cbcFinalIndexs[epoch]
	var vote *Vote
	if commitment == nil || !commitment[leader] {
		vote, _ = NewVote(c.Name, leader, epoch, round, FLAG_NO, c.SigService)
	} else {
		vote, _ = NewVote(c.Name, leader, epoch, round, FLAG_YES, c.SigService)
	}
	c.Transimtor.Send(c.Name, core.NONE, vote)
	c.Transimtor.RecvChannel() <- vote
	return nil
}

func (c *Core) handleVote(vote *Vote) error {
	logger.Debug.Printf("Processing vote epoch %d round %d leader %d val %d\n", vote.Epoch, vote.Round, vote.Leader, vote.Flag)
	if c.messageFilter(vote.Epoch) {
		return nil
	}
	if c.checkVote(vote) {
		return fmt.Errorf("vote check error epoch %d round %d author %d leader %d", vote.Epoch, vote.Round, vote.Author, vote.Leader)
	}

	if flag, err := c.Aggreator.addVote(vote); err != nil {
		return err
	} else if flag != ACTION_NO {
		var abaVal *ABAVal
		if flag == ACTION_ONE {
			abaVal, _ = NewABAVal(c.Name, vote.Leader, vote.Epoch, vote.Round, FLAG_YES, c.SigService)
		} else if flag == ACTION_TWO {
			abaVal, _ = NewABAVal(c.Name, vote.Leader, vote.Epoch, vote.Round, FLAG_NO, c.SigService)
		}
		c.Transimtor.Send(c.Name, core.NONE, abaVal)
		c.Transimtor.RecvChannel() <- abaVal
	}

	return nil
}

func (c *Core) handleABAVal(val *ABAVal) error {
	logger.Debug.Printf("Processing aba val leader %d epoch %d val %d\n", val.Leader, val.Epoch, val.Flag)
	if c.messageFilter(val.Epoch) {
		return nil
	}

	return nil
}

func (c *Core) handleABAMux(mux *ABAMux) error {
	logger.Debug.Printf("Processing aba mux leader %d epoch %d val %d\n", mux.Leader, mux.Epoch, mux.Flag)
	if c.messageFilter(mux.Epoch) {
		return nil
	}

	return nil
}

func (c *Core) handleCoinShare(share *CoinShare) error {
	logger.Debug.Printf("Processing coin share epoch %d", share.Epoch)
	if c.messageFilter(share.Epoch) {
		return nil
	}

	return nil
}

func (c *Core) handleABAHalt(halt *ABAHalt) error {
	logger.Debug.Printf("Processing aba halt leader %d epoch %d\n", halt.Leader, halt.Epoch)
	if c.messageFilter(halt.Epoch) {
		return nil
	}

	return nil
}

/**************************** Protocol ********************************/

func (c *Core) Run() {
	block := c.generateBlock(c.Epoch)
	proposal, err := NewProposal(c.Name, block, c.Epoch, c.SigService)
	if err != nil {
		panic(err)
	}
	c.Transimtor.Send(c.Name, core.NONE, proposal)
	c.Transimtor.RecvChannel() <- proposal

	recvChan := c.Transimtor.RecvChannel()
	for {
		var err error
		select {
		case msg := <-recvChan:
			{
				if v, ok := msg.(Validator); ok {
					if !v.Verify(c.Committee) {
						err = core.ErrSignature(msg.MsgType())
					}
				}

				switch msg.MsgType() {
				case ProposalType:
					err = c.handleProposal(msg.(*Proposal))
				case CommitmentType:
					err = c.handleCommitment(msg.(*Commitment))
				case ReadyType:
					err = c.handleReady(msg.(*Ready))
				case FinalType:
					err = c.handleFinal(msg.(*Final))
				case ElectShareType:
					err = c.handleElectShare(msg.(*ElectShare))
				case VoteType:
					err = c.handleVote(msg.(*Vote))
				case ABAValType:
					err = c.handleABAVal(msg.(*ABAVal))
				case ABAMuxType:
					err = c.handleABAMux(msg.(*ABAMux))
				case CoinShareType:
					err = c.handleCoinShare(msg.(*CoinShare))
				case ABAHaltType:
					err = c.handleABAHalt(msg.(*ABAHalt))
				}

			}
		case cbcBack := <-c.cbcCallBack:
			err = c.processCBCBack(cbcBack)
		}
		if err != nil {
			logger.Warn.Println(err)
		}
	}
}
