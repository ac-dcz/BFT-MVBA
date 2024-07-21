package consensus

import (
	"bft/mvba/core"
	"sync"
	"sync/atomic"
)

const (
	ABA_INVOKE = iota
	ABA_HALT
)

type ABABack struct {
	Typ     int
	Epoch   int64
	ExRound int64
	InRound int64
	Flag    uint8
	Leader  core.NodeID
}

type ABA struct {
	c           *Core
	Epoch       int64
	ExRound     int64
	valMutex    sync.Mutex
	valYesCnt   map[int64]int
	valNoCnt    map[int64]int
	flagMutex   sync.Mutex
	muxFlag     map[int64]struct{}
	muxFinFlag  map[int64]struct{}
	yesFlag     map[int64]struct{}
	noFlag      map[int64]struct{}
	muxMutex    sync.Mutex
	muxYesCnt   map[int64]int
	muxNoCnt    map[int64]int
	halt        atomic.Bool
	abaCallBack chan *ABABack
}

func NewABA(c *Core, Epoch, ExRound int64, abaCallBack chan *ABABack) *ABA {
	return &ABA{
		c:           c,
		Epoch:       Epoch,
		ExRound:     ExRound,
		valYesCnt:   map[int64]int{},
		valNoCnt:    map[int64]int{},
		muxFlag:     map[int64]struct{}{},
		muxFinFlag:  map[int64]struct{}{},
		yesFlag:     map[int64]struct{}{},
		noFlag:      map[int64]struct{}{},
		muxYesCnt:   map[int64]int{},
		muxNoCnt:    map[int64]int{},
		abaCallBack: abaCallBack,
	}
}

func (aba *ABA) ProcessABAVal(val *ABAVal) {
	if aba.halt.Load() {
		return
	}
	var cnt int
	aba.valMutex.Lock()
	if val.Flag == FLAG_NO {
		aba.valNoCnt[val.InRound]++
		cnt = aba.valNoCnt[val.InRound]
	} else if val.Flag == FLAG_YES {
		aba.valYesCnt[val.InRound]++
		cnt = aba.valYesCnt[val.InRound]
	}
	aba.valMutex.Unlock()

	if cnt == aba.c.Committee.LowThreshold() {
		aba.abaCallBack <- &ABABack{
			Typ:     ABA_INVOKE,
			Epoch:   aba.Epoch,
			ExRound: aba.ExRound,
			InRound: val.InRound,
			Flag:    val.Flag,
			Leader:  val.Leader,
		}
	} else if cnt == aba.c.Committee.HightThreshold() {
		aba.flagMutex.Lock()
		defer aba.flagMutex.Unlock()
		if _, ok := aba.muxFlag[val.InRound]; !ok {
			aba.muxFlag[val.InRound] = struct{}{}
			mux, _ := NewABAMux(aba.c.Name, val.Leader, val.Epoch, val.Round, val.InRound, val.Flag, aba.c.SigService)
			aba.c.Transimtor.Send(aba.c.Name, core.NONE, mux)
			aba.c.Transimtor.RecvChannel() <- mux
		}
	}

}

func (aba *ABA) ProcessABAMux(mux *ABAMux) {
	if aba.halt.Load() {
		return
	}
	aba.flagMutex.Lock()
	if _, ok := aba.muxFinFlag[mux.InRound]; ok {
		aba.flagMutex.Unlock()
		return
	}
	aba.flagMutex.Unlock()

	var muxYescnt, muxNocnt int
	aba.muxMutex.Lock()
	if mux.Flag == FLAG_NO {
		aba.muxNoCnt[mux.InRound]++
	} else if mux.Flag == FLAG_YES {
		aba.muxYesCnt[mux.InRound]++
	}
	muxYescnt, muxNocnt = aba.muxYesCnt[mux.InRound], aba.muxNoCnt[mux.InRound]
	aba.muxMutex.Unlock()

	var valYescnt, valNocnt int
	aba.valMutex.Lock()
	valYescnt, valNocnt = aba.valYesCnt[mux.InRound], aba.valNoCnt[mux.InRound]
	aba.valMutex.Unlock()

	var flag bool
	th := aba.c.Committee.HightThreshold()

	aba.flagMutex.Lock()
	if _, ok := aba.muxFinFlag[mux.InRound]; ok { //double check
		aba.flagMutex.Unlock()
		return
	}
	if muxYescnt+muxNocnt >= th {
		if valYescnt >= th && valNocnt >= th {
			if muxYescnt > 0 {
				aba.yesFlag[mux.InRound] = struct{}{}
				aba.muxFinFlag[mux.InRound] = struct{}{}
				flag = true
			}
			if muxNocnt > 0 {
				aba.noFlag[mux.InRound] = struct{}{}
				aba.muxFinFlag[mux.InRound] = struct{}{}
				flag = true
			}
		} else if valYescnt >= th && muxYescnt >= th {
			aba.yesFlag[mux.InRound] = struct{}{}
			aba.muxFinFlag[mux.InRound] = struct{}{}
			flag = true
		} else if valNocnt >= th && muxNocnt >= th {
			aba.noFlag[mux.InRound] = struct{}{}
			aba.muxFinFlag[mux.InRound] = struct{}{}
			flag = true
		}
	}
	aba.flagMutex.Unlock()

	if flag { //only once call
		coinShare, _ := NewCoinShare(aba.c.Name, mux.Leader, mux.Epoch, mux.Round, mux.InRound, aba.c.SigService)
		aba.c.Transimtor.Send(aba.c.Name, core.NONE, coinShare)
		aba.c.Transimtor.RecvChannel() <- coinShare
	}

}

func (aba *ABA) ProcessCoin(inRound int64, coin uint8, Leader core.NodeID) {
	aba.flagMutex.Lock()
	defer aba.flagMutex.Unlock()
	_, okYes := aba.yesFlag[inRound]
	_, okNo := aba.noFlag[inRound]

	if (okYes && okNo) || (!okYes && !okNo) { //next round with coin
		abaVal, _ := NewABAVal(aba.c.Name, Leader, aba.Epoch, aba.ExRound, inRound+1, coin, aba.c.SigService)
		aba.c.Transimtor.Send(aba.c.Name, core.NONE, abaVal)
		aba.c.Transimtor.RecvChannel() <- abaVal
	} else if (okYes && coin == FLAG_YES) || (okNo && coin == FLAG_NO) {
		halt, _ := NewABAHalt(aba.c.Name, Leader, aba.Epoch, aba.ExRound, inRound, coin, aba.c.SigService)
		aba.c.Transimtor.Send(aba.c.Name, core.NONE, halt)
		aba.c.Transimtor.RecvChannel() <- halt
	} else { // next round with self
		var abaVal *ABAVal
		if okYes {
			abaVal, _ = NewABAVal(aba.c.Name, Leader, aba.Epoch, aba.ExRound, inRound+1, FLAG_YES, aba.c.SigService)
		} else if okNo {
			abaVal, _ = NewABAVal(aba.c.Name, Leader, aba.Epoch, aba.ExRound, inRound+1, FLAG_NO, aba.c.SigService)
		}
		aba.c.Transimtor.Send(aba.c.Name, core.NONE, abaVal)
		aba.c.Transimtor.RecvChannel() <- abaVal
	}
}

func (aba *ABA) ProcessHalt(halt *ABAHalt) {
	aba.flagMutex.Lock()
	defer aba.flagMutex.Unlock()
	if aba.halt.Load() {
		return
	}
	aba.halt.Store(true)
	temp, _ := NewABAHalt(aba.c.Name, halt.Leader, aba.Epoch, aba.ExRound, halt.InRound, halt.Flag, aba.c.SigService)
	aba.c.Transimtor.Send(aba.c.Name, core.NONE, temp)
	aba.c.Transimtor.RecvChannel() <- temp

	aba.abaCallBack <- &ABABack{
		Typ:     ABA_HALT,
		Epoch:   halt.Epoch,
		ExRound: halt.Round,
		InRound: halt.InRound,
		Flag:    halt.Flag,
		Leader:  halt.Leader,
	}
}
