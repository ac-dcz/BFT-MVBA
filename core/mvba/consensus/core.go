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
	CallBack   chan struct{}
	Epoch      int64
}

func NewCore(
	name core.NodeID,
	committee core.Committee,
	parameters core.Parameters,
	SigService *crypto.SigService,
	Store *store.Store,
	TxPool *pool.Pool,
	Transimtor *core.Transmitor,
) *Core {
	core := &Core{
		Name:       name,
		Committee:  committee,
		Parameters: parameters,
		SigService: SigService,
		Store:      Store,
		TxPool:     TxPool,
		Transimtor: Transimtor,
	}

	return core
}

func (c *Core) messageFilter(epoch int64) bool {
	return c.Epoch > epoch
}

/**************************** Protocol ********************************/

func (c *Core) handleProposal(p *Proposal) error {
	logger.Debug.Printf("Processing proposal proposer %d epoch %d\n", p.Author, p.Epoch)
	if c.messageFilter(p.Epoch) {
		return nil
	}

	return nil
}

func (c *Core) handleReady(r *Ready) error {
	logger.Debug.Printf("Processing ready Tag %d epoch %d\n", r.Tag, r.Epoch)
	if c.messageFilter(r.Epoch) {
		return nil
	}

	return nil
}

func (c *Core) handleFinal(f *Final) error {
	logger.Debug.Printf("Processing final Tag %d epoch %d\n", f.Tag, f.Epoch)
	if c.messageFilter(f.Epoch) {
		return nil
	}

	return nil
}

func (c *Core) handleCommitment(commit *Commitment) error {
	logger.Debug.Printf("Processing commitment epoch %d\n", commit.Epoch)
	if c.messageFilter(commit.Epoch) {
		return nil
	}
	return nil
}

func (c *Core) handleElectShare(elect *ElectShare) error {
	logger.Debug.Printf("Processing electsahre epoch %d\n", elect.Epoch)
	if c.messageFilter(elect.Epoch) {
		return nil
	}

	return nil
}

func (c *Core) handleVote(vote *Vote) error {
	logger.Debug.Printf("Processing vote epoch %d val %d\n", vote.Epoch, vote.Flag)
	if c.messageFilter(vote.Epoch) {
		return nil
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
		default:
		}
		if err != nil {
			logger.Warn.Println(err)
		}
	}

}
