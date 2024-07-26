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
	Commitor       *Commitor
	Elector        *Elector
	Aggreator      *Aggreator
	Epoch          int64
	cbcCallBack    chan *CBCBack
	cbcInstances   map[int64]map[core.NodeID]map[uint8]*CBC //epoch-node-tag
	cbcFinalCnts   map[int64]map[uint8]int                  //epoch-tag finish-cbc cnts
	cbcFinalIndexs map[int64][]bool                         //epoch self-commitment
	commitments    map[int64]map[core.NodeID][]bool         //epoch-node commitment
	abaInstances   map[int64]map[int64]*ABA
	abaInvokeFlag  map[int64]map[int64]map[int64]map[uint8]struct{} //aba invoke flag
	abaCallBack    chan *ABABack
}

func NewCore(
	name core.NodeID,
	committee core.Committee,
	parameters core.Parameters,
	SigService *crypto.SigService,
	Store *store.Store,
	TxPool *pool.Pool,
	Transimtor *core.Transmitor,
	CallBack chan<- struct{},
) *Core {
	core := &Core{
		Name:           name,
		Committee:      committee,
		Parameters:     parameters,
		SigService:     SigService,
		Store:          Store,
		TxPool:         TxPool,
		Transimtor:     Transimtor,
		Commitor:       NewCommitor(CallBack),
		Elector:        NewElector(committee, SigService),
		Aggreator:      NewAggreator(committee, SigService),
		Epoch:          0,
		cbcCallBack:    make(chan *CBCBack, 1000),
		cbcInstances:   make(map[int64]map[core.NodeID]map[uint8]*CBC),
		cbcFinalCnts:   make(map[int64]map[uint8]int),
		cbcFinalIndexs: make(map[int64][]bool),
		commitments:    make(map[int64]map[core.NodeID][]bool),
		abaInstances:   make(map[int64]map[int64]*ABA),
		abaInvokeFlag:  make(map[int64]map[int64]map[int64]map[uint8]struct{}),
		abaCallBack:    make(chan *ABABack, 1000),
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

func (c *Core) getBlock(digest crypto.Digest) (*Block, error) {
	data, err := c.Store.Read(digest[:])
	if err != nil {
		return nil, err
	}
	block := &Block{}
	err = block.Decode(data)
	return block, err
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
		instance = NewABA(c, epoch, round, c.abaCallBack)
		items[round] = instance
	}
	return instance
}

func (c *Core) isInvokeABA(epoch, round, inRound int64, tag uint8) bool {
	flags, ok := c.abaInvokeFlag[epoch]
	if !ok {
		return false
	}
	flag, ok := flags[round]
	if !ok {
		return false
	}
	item, ok := flag[inRound]
	if !ok {
		return false
	}
	_, ok = item[tag]
	return ok
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

	if c.Commitor.CommitLeader(p.Epoch) == p.Author {
		c.Commitor.Commit(p.Epoch, p.Author, p.B)
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
	go c.getCBCInstance(r.Epoch, r.Proposer, r.Tag).ProcessReady(r)
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
		if flag == ACTION_ONE {
			return c.invokeABAVal(vote.Leader, vote.Epoch, vote.Round, 0, FLAG_YES)
		} else {
			return c.invokeABAVal(vote.Leader, vote.Epoch, vote.Round, 0, FLAG_NO)
		}
	}

	return nil
}

func (c *Core) invokeABAVal(leader core.NodeID, epoch, round, inRound int64, flag uint8) error {
	logger.Debug.Printf("Invoke ABA epoch %d ex_round %d in_round %d val %d\n", epoch, round, inRound, flag)
	if c.isInvokeABA(epoch, round, inRound, flag) {
		return nil
	}
	flags, ok := c.abaInvokeFlag[epoch]
	if !ok {
		flags = make(map[int64]map[int64]map[uint8]struct{})
		c.abaInvokeFlag[epoch] = flags
	}
	items, ok := flags[round]
	if !ok {
		items = make(map[int64]map[uint8]struct{})
		flags[round] = items
	}
	item, ok := items[inRound]
	if !ok {
		item = make(map[uint8]struct{})
		items[inRound] = item
	}
	item[flag] = struct{}{}
	abaVal, _ := NewABAVal(c.Name, leader, epoch, round, inRound, flag, c.SigService)
	c.Transimtor.Send(c.Name, core.NONE, abaVal)
	c.Transimtor.RecvChannel() <- abaVal

	return nil
}

func (c *Core) handleABAVal(val *ABAVal) error {
	logger.Debug.Printf("Processing aba val leader %d epoch %d round %d in-round val %d\n", val.Leader, val.Epoch, val.Round, val.InRound, val.Flag)
	if c.messageFilter(val.Epoch) {
		return nil
	}

	go c.getABAInstance(val.Epoch, val.Round).ProcessABAVal(val)

	return nil
}

func (c *Core) handleABAMux(mux *ABAMux) error {
	logger.Debug.Printf("Processing aba mux leader %d epoch %d round %d in-round %d val %d\n", mux.Leader, mux.Epoch, mux.Round, mux.InRound, mux.Flag)
	if c.messageFilter(mux.Epoch) {
		return nil
	}

	go c.getABAInstance(mux.Epoch, mux.Round).ProcessABAMux(mux)

	return nil
}

func (c *Core) handleCoinShare(share *CoinShare) error {
	logger.Debug.Printf("Processing coin share epoch %d round %d in-round %d", share.Epoch, share.Round, share.InRound)
	if c.messageFilter(share.Epoch) {
		return nil
	}

	if ok, coin, err := c.Aggreator.addCoinShare(share); err != nil {
		return err
	} else if ok {
		logger.Debug.Printf("ABA epoch %d ex-round %d in-round %d coin %d\n", share.Epoch, share.Round, share.InRound, coin)
		go c.getABAInstance(share.Epoch, share.Round).ProcessCoin(share.InRound, coin, share.Leader)
	}

	return nil
}

func (c *Core) handleABAHalt(halt *ABAHalt) error {
	logger.Debug.Printf("Processing aba halt leader %d epoch %d in-round %d\n", halt.Leader, halt.Epoch, halt.InRound)
	if c.messageFilter(halt.Epoch) {
		return nil
	}
	go c.getABAInstance(halt.Epoch, halt.Round).ProcessHalt(halt)
	return nil
}

func (c *Core) processABABack(back *ABABack) error {
	if back.Typ == ABA_INVOKE {
		return c.invokeABAVal(back.Leader, back.Epoch, back.ExRound, back.InRound, back.Flag)
	} else if back.Typ == ABA_HALT {
		if back.Flag == FLAG_NO { //next round
			return c.invokeStageTwo(back.Epoch, back.ExRound+1)
		} else if back.Flag == FLAG_YES { //next epoch
			return c.handleOutput(back.Epoch, back.Leader)
		}
	}
	return nil
}

func (c *Core) handleOutput(epoch int64, leader core.NodeID) error {
	cbc := c.getCBCInstance(epoch, leader, DATA_CBC)
	if cbc.BlockHash != nil {
		if block, err := c.getBlock(*cbc.BlockHash); err != nil {
			logger.Warn.Println(err)
			c.Commitor.Commit(epoch, leader, nil)
		} else {
			c.Commitor.Commit(epoch, leader, block)
			if block.Proposer != c.Name {
				temp := c.getCBCInstance(epoch, c.Name, DATA_CBC).BlockHash
				if temp != nil {
					if block, err := c.getBlock(*temp); err == nil && block != nil {
						c.TxPool.PutBatch(block.Batch)
					}
				}
			}
		}
	}
	return c.abvanceNextEpoch(epoch + 1)
}

/**************************** Protocol ********************************/

func (c *Core) abvanceNextEpoch(epoch int64) error {
	if epoch <= c.Epoch {
		return nil
	}
	logger.Debug.Printf("advance next epoch %d\n", epoch)
	c.Epoch = epoch
	block := c.generateBlock(c.Epoch)
	proposal, _ := NewProposal(c.Name, block, c.Epoch, c.SigService)
	c.Transimtor.Send(c.Name, core.NONE, proposal)
	c.Transimtor.RecvChannel() <- proposal
	return nil
}

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
		case abaBack := <-c.abaCallBack:
			err = c.processABABack(abaBack)
		}

		if err != nil {
			logger.Warn.Println(err)
		}
	}
}
