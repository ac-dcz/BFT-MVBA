package consensus

import "bft/mvba/core"

type Aggreator struct {
	committee       core.Committee
	finishAggreator map[int64]map[int64]*FinishAggreator
}

func NewAggreator(committee core.Committee) *Aggreator {
	return &Aggreator{
		committee:       committee,
		finishAggreator: make(map[int64]map[int64]*FinishAggreator),
	}
}

func (a *Aggreator) AddFinishVote(finish *Finish) (bool, error) {
	items, ok := a.finishAggreator[finish.Epoch]
	if !ok {
		items = make(map[int64]*FinishAggreator)
	}
	if item, ok := items[finish.Round]; ok {
		return item.Append(a.committee, finish)
	} else {
		item = NewFinishAggreator()
		items[finish.Round] = NewFinishAggreator()
		return item.Append(a.committee, finish)
	}
}

type FinishAggreator struct {
	Authors map[core.NodeID]struct{}
}

func NewFinishAggreator() *FinishAggreator {
	return &FinishAggreator{
		Authors: make(map[core.NodeID]struct{}),
	}
}

func (f *FinishAggreator) Append(committee core.Committee, finish *Finish) (bool, error) {
	if _, ok := f.Authors[finish.Author]; ok {
		return false, core.ErrOneMoreMessage(finish.MsgType(), finish.Epoch, finish.Round, finish.Author)
	}
	f.Authors[finish.Author] = struct{}{}
	if len(f.Authors) == committee.HightThreshold() {
		return true, nil
	}
	return false, nil
}
