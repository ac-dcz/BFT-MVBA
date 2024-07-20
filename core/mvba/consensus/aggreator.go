package consensus

import (
	"bft/mvba/core"
)

type Aggreator struct {
	committee core.Committee
	votes     map[int64]map[int64]*VoteAggreator
}

func NewAggreator(committee core.Committee) *Aggreator {
	a := &Aggreator{
		committee: committee,
		votes:     make(map[int64]map[int64]*VoteAggreator),
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
