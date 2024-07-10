package consensus

import (
	"bft/mvba/core"
	"bft/mvba/crypto"
)

type Aggreator struct {
	committee        core.Committee
	finishAggreator  map[int64]map[int64]*FinishAggreator
	doneAggreator    map[int64]map[int64]*DoneAggreator
	prevoteAggreator map[int64]map[int64]*PreVoteAggreator
	finvoteAggreator map[int64]map[int64]*FinVoteAggreator
}

func NewAggreator(committee core.Committee) *Aggreator {
	return &Aggreator{
		committee:        committee,
		finishAggreator:  make(map[int64]map[int64]*FinishAggreator),
		doneAggreator:    make(map[int64]map[int64]*DoneAggreator),
		prevoteAggreator: make(map[int64]map[int64]*PreVoteAggreator),
		finvoteAggreator: make(map[int64]map[int64]*FinVoteAggreator),
	}
}

func (a *Aggreator) AddFinishVote(finish *Finish) (bool, error) {
	items, ok := a.finishAggreator[finish.Epoch]
	if !ok {
		items = make(map[int64]*FinishAggreator)
		a.finishAggreator[finish.Epoch] = items
	}
	if item, ok := items[finish.Round]; ok {
		return item.Append(a.committee, finish)
	} else {
		item = NewFinishAggreator()
		items[finish.Round] = NewFinishAggreator()
		return item.Append(a.committee, finish)
	}
}

func (a *Aggreator) AddDoneVote(done *Done) (int8, error) {
	items, ok := a.doneAggreator[done.Epoch]
	if !ok {
		items = make(map[int64]*DoneAggreator)
		a.doneAggreator[done.Epoch] = items
	}
	if item, ok := items[done.Round]; ok {
		return item.Append(a.committee, done)
	} else {
		item = NewDoneAggreator()
		items[done.Round] = item
		return item.Append(a.committee, done)
	}
}

func (a *Aggreator) AddPreVote(vote *Prevote) (int8, error) {
	items, ok := a.prevoteAggreator[vote.Epoch]
	if !ok {
		items = make(map[int64]*PreVoteAggreator)
		a.prevoteAggreator[vote.Epoch] = items
	}
	if item, ok := items[vote.Round]; ok {
		return item.Append(a.committee, vote)
	} else {
		item = NewPrevoteAggreator()
		items[vote.Round] = item
		return item.Append(a.committee, vote)
	}
}

func (a *Aggreator) AddFinVote(vote *FinVote) (int8, error) {
	items, ok := a.finvoteAggreator[vote.Epoch]
	if !ok {
		items = make(map[int64]*FinVoteAggreator)
		a.finvoteAggreator[vote.Epoch] = items
	}
	if item, ok := items[vote.Round]; ok {
		return item.Append(a.committee, vote)
	} else {
		item = NewFinVoteAggreator()
		items[vote.Round] = item
		return item.Append(a.committee, vote)
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

const (
	DONE_LOW_FLAG int8 = iota
	DONE_HIGH_FLAG
	DONE_NONE_FLAG
)

type DoneAggreator struct {
	Authors map[core.NodeID]struct{}
}

func NewDoneAggreator() *DoneAggreator {
	return &DoneAggreator{
		Authors: make(map[core.NodeID]struct{}),
	}
}

func (d *DoneAggreator) Append(committee core.Committee, done *Done) (int8, error) {
	if _, ok := d.Authors[done.Author]; ok {
		return 0, core.ErrOneMoreMessage(done.MsgType(), done.Epoch, done.Round, done.Author)
	}
	d.Authors[done.Author] = struct{}{}
	if len(d.Authors) == committee.LowThreshold() {
		return DONE_LOW_FLAG, nil
	}
	if len(d.Authors) == committee.HightThreshold() {
		return DONE_HIGH_FLAG, nil
	}
	return DONE_NONE_FLAG, nil
}

const RANDOM_LEN = 3

type ElectAggreator struct {
	shares  []crypto.SignatureShare
	authors map[core.NodeID]struct{}
}

func NewElectAggreator() *ElectAggreator {
	return &ElectAggreator{
		shares:  make([]crypto.SignatureShare, 0),
		authors: make(map[core.NodeID]struct{}),
	}
}

func (e *ElectAggreator) Append(committee core.Committee, sigService *crypto.SigService, elect *ElectShare) (core.NodeID, error) {
	if _, ok := e.authors[elect.Author]; ok {
		return core.NONE, core.ErrOneMoreMessage(elect.MsgType(), elect.Epoch, elect.Round, elect.Author)
	}
	e.authors[elect.Author] = struct{}{}
	e.shares = append(e.shares, elect.SigShare)
	if len(e.shares) == committee.HightThreshold() {
		coin, err := crypto.CombineIntactTSPartial(e.shares, sigService.ShareKey, elect.Hash())
		if err != nil {
			return core.NONE, err
		}
		var rand int
		for i := 0; i < RANDOM_LEN; i++ {
			if coin[i] > 0 {
				rand = rand<<8 + int(coin[i])
			} else {
				rand = rand<<8 + int(-coin[i])
			}
		}
		return core.NodeID(rand) % core.NodeID(committee.Size()), nil
	}
	return core.NONE, nil
}

const (
	ACTION_YES int8 = iota
	ACTION_NO
	ACTION_COMMIT
	ACTION_NONE
)

type PreVoteAggreator struct {
	authors map[core.NodeID]struct{}
	yesNums int64
	noNums  int64
	flag    bool
}

func NewPrevoteAggreator() *PreVoteAggreator {
	return &PreVoteAggreator{
		authors: make(map[core.NodeID]struct{}),
		yesNums: 0,
		noNums:  0,
		flag:    false,
	}
}

func (p *PreVoteAggreator) Append(committee core.Committee, vote *Prevote) (int8, error) {
	if _, ok := p.authors[vote.Author]; ok {
		return ACTION_NONE, core.ErrOneMoreMessage(vote.MsgType(), vote.Epoch, vote.Round, vote.Author)
	}
	p.authors[vote.Author] = struct{}{}
	if vote.Flag == VOTE_FLAG_NO {
		p.noNums++
	} else {
		p.yesNums++
	}

	if p.yesNums > 0 && !p.flag {
		p.flag = true
		return ACTION_YES, nil
	}
	if p.noNums == int64(committee.HightThreshold()) && !p.flag {
		return ACTION_NO, nil
	}
	return ACTION_NONE, nil
}

type FinVoteAggreator struct {
	authors map[core.NodeID]struct{}
	yesNums int64
	noNums  int64
}

func NewFinVoteAggreator() *FinVoteAggreator {
	return &FinVoteAggreator{
		authors: make(map[core.NodeID]struct{}),
		yesNums: 0,
		noNums:  0,
	}
}

func (f *FinVoteAggreator) Append(committee core.Committee, vote *FinVote) (int8, error) {
	if _, ok := f.authors[vote.Author]; ok {
		return ACTION_NONE, core.ErrOneMoreMessage(vote.MsgType(), vote.Epoch, vote.Round, vote.Author)
	}
	f.authors[vote.Author] = struct{}{}
	if vote.Flag == VOTE_FLAG_YES {
		f.yesNums++
	} else {
		f.noNums++
	}
	var th int64 = int64(committee.HightThreshold())
	if f.yesNums+f.noNums == th {
		if f.yesNums == th {
			return ACTION_COMMIT, nil
		} else if f.noNums == th {
			return ACTION_NO, nil
		}
		return ACTION_YES, nil
	}
	return ACTION_NONE, nil
}
