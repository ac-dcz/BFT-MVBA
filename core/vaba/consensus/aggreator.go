package consensus

import "bft/mvba/core"

type Aggreator struct {
	committee     core.Committee
	doneAggreator map[int64]*normalAggreator
	skipAggreator map[int64]*normalAggreator
}

func NewAggreator(committee core.Committee) *Aggreator {
	return &Aggreator{
		committee:     committee,
		doneAggreator: make(map[int64]*normalAggreator),
		skipAggreator: make(map[int64]*normalAggreator),
	}
}

func (a *Aggreator) addDoneVote(done *Done) (bool, error) {
	item, ok := a.doneAggreator[done.Epoch]
	if !ok {
		item = newNormalAggreator()
		a.doneAggreator[done.Epoch] = item
	}
	return item.Append(done.Author, a.committee, done.MsgType(), done.Epoch)
}

func (a *Aggreator) addSkipVote(share *SkipShare) (bool, error) {
	item, ok := a.skipAggreator[share.Epoch]
	if !ok {
		item = newNormalAggreator()
		a.doneAggreator[share.Epoch] = item
	}
	return item.Append(share.Author, a.committee, share.MsgType(), share.Epoch)
}

type normalAggreator struct {
	Authors map[core.NodeID]struct{}
}

func newNormalAggreator() *normalAggreator {
	return &normalAggreator{
		Authors: make(map[core.NodeID]struct{}),
	}
}

func (a *normalAggreator) Append(node core.NodeID, committee core.Committee, mType int, epoch int64) (bool, error) {
	if _, ok := a.Authors[node]; ok {
		return false, core.ErrOneMoreMessage(mType, epoch, 0, node)
	}
	a.Authors[node] = struct{}{}
	if len(a.Authors) == committee.HightThreshold() {
		return true, nil
	}
	return false, nil
}
