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

	FinishFlags  map[int64]map[int]struct{} // finish? map[epoch][nodeId]
	SPbInstances map[int64]map[int64]*SPB   // map[epoch][round]

	Epoch int64
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
		FinishFlags:  make(map[int64]map[int]struct{}),
		SPbInstances: make(map[int64]map[int64]*SPB),
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

func (c *Core) getSpbInstance(epoch, round int64) *SPB {
	rItems, ok := c.SPbInstances[epoch]
	if !ok {
		rItems = make(map[int64]*SPB)
	}
	instance := NewSPB(c, epoch, round)
	rItems[round] = instance

	return instance
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

	spb := c.getSpbInstance(p.Epoch, p.Round)
	go spb.processProposal(p)

	return nil
}

func (c *Core) handleSpbVote(v *SPBVote) error {
	logger.Debug.Printf("Processing SPBVote epoch %d round %d phase %d\n", v.Epoch, v.Round, v.Phase)

	//discard message
	if c.messgaeFilter(v.Epoch) {
		return nil
	}

	spb := c.getSpbInstance(v.Epoch, v.Round)
	go spb.processVote(v)

	return nil
}

func (c *Core) handleFinish(f *Finish) error {
	logger.Debug.Printf("Processing Finish epoch %d round %d\n", f.Epoch, f.Round)

	//discard message
	if c.messgaeFilter(f.Epoch) {
		return nil
	}

	return nil
}

func (c *Core) handleDone(d *Done) error {
	logger.Debug.Printf("Processing Done epoch %d round %d\n", d.Epoch, d.Round)

	//discard message
	if c.messgaeFilter(d.Epoch) {
		return nil
	}

	return nil
}

func (c *Core) handleElectShare(share *ElectShare) error {
	logger.Debug.Printf("Processing ElectShare epoch %d round %d\n", share.Epoch, share.Round)

	//discard message
	if c.messgaeFilter(share.Epoch) {
		return nil
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
