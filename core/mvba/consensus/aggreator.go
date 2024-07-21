package consensus

import (
	"bft/mvba/core"
	"bft/mvba/crypto"
	"bft/mvba/logger"
)

type Aggreator struct {
	committee  core.Committee
	sigService *crypto.SigService
	votes      map[int64]map[int64]*VoteAggreator           //epoch-exround
	coins      map[int64]map[int64]map[int64]*CoinAggreator //epoch-exround-inround
}

func NewAggreator(committee core.Committee, sigService *crypto.SigService) *Aggreator {
	a := &Aggreator{
		committee:  committee,
		sigService: sigService,
		votes:      make(map[int64]map[int64]*VoteAggreator),
		coins:      make(map[int64]map[int64]map[int64]*CoinAggreator),
	}

	return a
}

func (a *Aggreator) addVote(vote *Vote) (uint8, error) {
	items, ok := a.votes[vote.Epoch]
	if !ok {
		items = make(map[int64]*VoteAggreator)
		a.votes[vote.Round] = items
	}
	item, ok := items[vote.Round]
	if !ok {
		item = NewVoteAggreator()
		items[vote.Round] = item
	}
	return item.append(a.committee, vote)
}

func (a *Aggreator) addCoinShare(coinShare *CoinShare) (bool, uint8, error) {
	items, ok := a.coins[coinShare.Epoch]
	if !ok {
		items = make(map[int64]map[int64]*CoinAggreator)
		items[coinShare.Round] = make(map[int64]*CoinAggreator)
		a.coins[coinShare.Epoch] = items
	}
	instance, ok := items[coinShare.Round][coinShare.InRound]
	if !ok {
		instance = NewCoinAggreator()
		items[coinShare.Round][coinShare.InRound] = instance
	}
	return instance.append(a.committee, a.sigService, coinShare)
}

const (
	ACTION_NO uint8 = iota
	ACTION_ONE
	ACTION_TWO
)

type VoteAggreator struct {
	Used map[core.NodeID]struct{}
	flag bool
}

func NewVoteAggreator() *VoteAggreator {
	return &VoteAggreator{
		Used: make(map[core.NodeID]struct{}),
		flag: false,
	}
}

func (v *VoteAggreator) append(committee core.Committee, vote *Vote) (uint8, error) {
	if _, ok := v.Used[vote.Author]; ok {
		return ACTION_NO, core.ErrOneMoreMessage(vote.MsgType(), vote.Epoch, vote.Round, vote.Author)
	}
	v.Used[vote.Author] = struct{}{}
	if !v.flag && vote.Flag == FLAG_YES {
		v.flag = true
		return ACTION_ONE, nil
	}
	if !v.flag && len(v.Used) == committee.HightThreshold() {
		v.flag = true
		return ACTION_TWO, nil
	}
	return ACTION_NO, nil
}

type CoinAggreator struct {
	Used   map[core.NodeID]struct{}
	Shares []crypto.SignatureShare
}

func NewCoinAggreator() *CoinAggreator {
	return &CoinAggreator{
		Used:   make(map[core.NodeID]struct{}),
		Shares: make([]crypto.SignatureShare, 0),
	}
}

func (c *CoinAggreator) append(committee core.Committee, sigService *crypto.SigService, share *CoinShare) (bool, uint8, error) {
	if _, ok := c.Used[share.Author]; ok {
		return false, 0, core.ErrOneMoreMessage(share.MsgType(), share.Epoch, share.Round, share.Author)
	}
	c.Shares = append(c.Shares, share.Share)
	if len(c.Shares) == committee.HightThreshold() {
		var seed uint64 = 0
		data, err := crypto.CombineIntactTSPartial(c.Shares, sigService.ShareKey, share.Hash())
		if err != nil {
			logger.Error.Printf("Combine signature error: %v\n", err)
			return false, 0, err
		}
		for i := 0; i < len(data) && i < RANDOM_LEN; i++ {
			seed = seed<<8 + uint64(data[i])
		}
		return true, uint8(seed % 2), nil
	}

	return false, 0, nil
}
