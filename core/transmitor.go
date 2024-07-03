package core

import (
	"bft/mvba/network"
)

type Messgae interface {
	MsgType() int
}

type Transmitor struct {
	sender     *network.Sender
	receiver   *network.Receiver
	recvCh     chan Messgae
	msgCh      chan *network.NetMessage
	parameters Parameters
	committee  Committee
}

func NewTransmitor(
	sender *network.Sender,
	receiver *network.Receiver,
	parameters Parameters,
	committee Committee,
) *Transmitor {

	tr := &Transmitor{
		sender:     sender,
		receiver:   receiver,
		recvCh:     make(chan Messgae, 1_000),
		msgCh:      make(chan *network.NetMessage, 1_000),
		parameters: parameters,
		committee:  committee,
	}

	go func() {
		for msg := range tr.msgCh {
			tr.sender.Send(msg)
		}
	}()

	go func() {
		for msg := range tr.receiver.RecvChannel() {
			tr.recvCh <- msg
		}
	}()

	return tr
}

func (tr *Transmitor) Send(from, to NodeID, msg Messgae) error {
	var addr []string

	if to == NONE {
		addr = tr.committee.BroadCast(from)
	} else {
		addr = append(addr, tr.committee.Address(to))
	}

	// // filter
	// if tr.parameters.DDos && (msg.MsgType() == GRBCProposeType || msg.MsgType() == PBCProposeType) {
	// 	time.AfterFunc(time.Millisecond*time.Duration(tr.parameters.NetwrokDelay), func() {
	// 		tr.msgCh <- &network.NetMessage{
	// 			Msg:     msg,
	// 			Address: addr,
	// 		}
	// 	})
	// } else {
	// 	tr.msgCh <- &network.NetMessage{
	// 		Msg:     msg,
	// 		Address: addr,
	// 	}
	// }
	tr.msgCh <- &network.NetMessage{
		Msg:     msg,
		Address: addr,
	}

	return nil
}

func (tr *Transmitor) Recv() Messgae {
	return <-tr.recvCh
}

func (tr *Transmitor) RecvChannel() chan Messgae {
	return tr.recvCh
}
