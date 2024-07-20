package consensus

type ABA struct {
	c       *Core
	Epoch   int64
	ExRound int64
	InRound int64
}

func NewABA(c *Core, Epoch, ExRound int64) *ABA {
	return &ABA{
		c:       c,
		Epoch:   Epoch,
		ExRound: ExRound,
		InRound: 0,
	}
}
