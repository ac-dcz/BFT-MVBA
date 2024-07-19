package consensus

import (
	"bft/mvba/core"
	"bft/mvba/crypto"
	"bft/mvba/pool"
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"reflect"
	"strconv"
)

const (
	FLAG_YES uint8 = 0
	FLAG_NO  uint8 = 1
)

type Validator interface {
	Verify(core.Committee) bool
}

type Block struct {
	Proposer core.NodeID
	Batch    pool.Batch
	Epoch    int64
}

func NewBlock(proposer core.NodeID, Batch pool.Batch, Epoch int64) *Block {
	return &Block{
		Proposer: proposer,
		Batch:    Batch,
		Epoch:    Epoch,
	}
}

func (b *Block) Encode() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := gob.NewEncoder(buf).Encode(b); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (b *Block) Decode(data []byte) error {
	buf := bytes.NewBuffer(data)
	if err := gob.NewDecoder(buf).Decode(b); err != nil {
		return err
	}
	return nil
}

func (b *Block) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(b.Proposer), 2))
	hasher.Add(strconv.AppendInt(nil, b.Epoch, 2))
	hasher.Add(strconv.AppendInt(nil, int64(b.Batch.ID), 2))
	return hasher.Sum256(nil)
}

type Proposal struct {
	Author    core.NodeID
	B         *Block
	Epoch     int64
	Signature crypto.Signature
}

func NewProposal(Author core.NodeID, B *Block, Epoch int64, sigService *crypto.SigService) (*Proposal, error) {
	proposal := &Proposal{
		Author: Author,
		B:      B,
		Epoch:  Epoch,
	}
	sig, err := sigService.RequestSignature(proposal.Hash())
	if err != nil {
		return nil, err
	}
	proposal.Signature = sig
	return proposal, nil
}

func (p *Proposal) Verify(committee core.Committee) bool {
	pub := committee.Name(p.Author)
	return p.Signature.Verify(pub, p.Hash())
}

func (p *Proposal) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(binary.LittleEndian.AppendUint64(nil, uint64(p.Author)))
	hasher.Add(binary.LittleEndian.AppendUint64(nil, uint64(p.Epoch)))
	d := p.B.Hash()
	hasher.Add(d[:])
	return hasher.Sum256(nil)
}

func (p *Proposal) MsgType() int {
	return ProposalType
}

type Commitment struct {
	Author    core.NodeID
	C         []bool
	Epoch     int64
	Signature crypto.Signature
}

func NewCommitment(Author core.NodeID, C []bool, Epoch int64, sigService *crypto.SigService) (*Commitment, error) {
	commitment := &Commitment{
		Author: Author,
		C:      C,
		Epoch:  Epoch,
	}
	sig, err := sigService.RequestSignature(commitment.Hash())
	if err != nil {
		return nil, err
	}
	commitment.Signature = sig
	return commitment, nil
}

func (c *Commitment) Verify(committee core.Committee) bool {
	pub := committee.Name(c.Author)
	return c.Signature.Verify(pub, c.Hash())
}

func (c *Commitment) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(binary.LittleEndian.AppendUint64(nil, uint64(c.Author)))
	hasher.Add(binary.LittleEndian.AppendUint64(nil, uint64(c.Epoch)))
	return hasher.Sum256(nil)
}

func (c *Commitment) MsgType() int {
	return CommitmentType
}

type Ready struct {
	Author    core.NodeID
	Proposer  core.NodeID
	Epoch     int64
	Tag       uint8
	Signature crypto.Signature
}

func NewReady(Author, Proposer core.NodeID, Epoch int64, tag uint8, sigService *crypto.SigService) (*Ready, error) {
	ready := &Ready{
		Author:   Author,
		Proposer: Proposer,
		Epoch:    Epoch,
		Tag:      tag,
	}
	sig, err := sigService.RequestSignature(ready.Hash())
	if err != nil {
		return nil, err
	}
	ready.Signature = sig
	return ready, nil
}

func (r *Ready) Verify(committee core.Committee) bool {
	pub := committee.Name(r.Author)
	return r.Signature.Verify(pub, r.Hash())
}

func (r *Ready) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(binary.LittleEndian.AppendUint64(nil, uint64(r.Author)))
	hasher.Add(binary.LittleEndian.AppendUint64(nil, uint64(r.Proposer)))
	hasher.Add(binary.LittleEndian.AppendUint64(nil, uint64(r.Epoch)))
	hasher.Add([]byte{r.Tag})
	return hasher.Sum256(nil)
}

func (r *Ready) MsgType() int {
	return ReadyType
}

type Final struct {
	Author    core.NodeID
	Epoch     int64
	Tag       uint8
	Signature crypto.Signature
}

func NewFinal(Author core.NodeID, Epoch int64, Tag uint8, sigService *crypto.SigService) (*Final, error) {
	f := &Final{
		Author: Author,
		Epoch:  Epoch,
		Tag:    Tag,
	}
	sig, err := sigService.RequestSignature(f.Hash())
	if err != nil {
		return nil, err
	}
	f.Signature = sig
	return f, nil
}

func (f *Final) Verify(committee core.Committee) bool {
	pub := committee.Name(f.Author)
	return f.Signature.Verify(pub, f.Hash())
}

func (f *Final) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(binary.LittleEndian.AppendUint64(nil, uint64(f.Author)))
	hasher.Add(binary.LittleEndian.AppendUint64(nil, uint64(f.Epoch)))
	hasher.Add([]byte{f.Tag})
	return hasher.Sum256(nil)
}

func (f *Final) MsgType() int {
	return FinalType
}

type ElectShare struct {
	Author core.NodeID
	Epoch  int64
	Share  crypto.SignatureShare
}

func NewElectShare(Author core.NodeID, Epoch int64, sigService *crypto.SigService) (*ElectShare, error) {
	e := &ElectShare{
		Author: Author,
		Epoch:  Epoch,
	}
	sig, err := sigService.RequestTsSugnature(e.Hash())
	if err != nil {
		return nil, err
	}
	e.Share = sig
	return e, nil
}

func (e *ElectShare) Verify(committee core.Committee) bool {
	_ = committee.Name(e.Author)
	return e.Share.Verify(e.Hash())
}

func (e *ElectShare) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(binary.LittleEndian.AppendUint64(nil, uint64(e.Epoch)))
	return hasher.Sum256(nil)
}

func (e *ElectShare) MsgType() int {
	return ElectShareType
}

type Vote struct {
	Author    core.NodeID
	Leader    core.NodeID
	Epoch     int64
	Flag      uint8
	Signature crypto.Signature
}

func NewVote(Author, Leader core.NodeID, Epoch int64, Flag uint8, sigService *crypto.SigService) (*Vote, error) {
	v := &Vote{
		Author: Author,
		Leader: Leader,
		Epoch:  Epoch,
		Flag:   Flag,
	}
	sig, err := sigService.RequestSignature(v.Hash())
	if err != nil {
		return nil, err
	}
	v.Signature = sig
	return v, nil
}

func (v *Vote) Verify(committee core.Committee) bool {
	pub := committee.Name(v.Author)
	return v.Signature.Verify(pub, v.Hash())
}

func (v *Vote) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(v.Author)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(v.Leader)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(v.Epoch)))
	hasher.Add([]byte{v.Flag})
	return hasher.Sum256(nil)
}

func (v *Vote) MsgType() int {
	return VoteType
}

type ABAVal struct {
	Author    core.NodeID
	Leader    core.NodeID
	Epoch     int64
	Flag      uint8
	Signature crypto.Signature
}

func NewABAVal(Author, Leader core.NodeID, Epoch int64, Flag uint8, sigService *crypto.SigService) (*ABAVal, error) {
	val := &ABAVal{
		Author: Author,
		Leader: Leader,
		Epoch:  Epoch,
		Flag:   Flag,
	}
	sig, err := sigService.RequestSignature(val.Hash())
	if err != nil {
		return nil, err
	}
	val.Signature = sig
	return val, nil
}

func (v *ABAVal) Verify(committee core.Committee) bool {
	pub := committee.Name(v.Author)
	return v.Signature.Verify(pub, v.Hash())
}

func (v *ABAVal) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(v.Author)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(v.Leader)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(v.Epoch)))
	hasher.Add([]byte{v.Flag})
	return hasher.Sum256(nil)
}

func (v *ABAVal) MsgType() int {
	return ABAValType
}

type ABAMux struct {
	Author    core.NodeID
	Leader    core.NodeID
	Epoch     int64
	Flag      uint8
	Signature crypto.Signature
}

func NewABAMux(Author, Leader core.NodeID, Epoch int64, Flag uint8, sigService *crypto.SigService) (*ABAMux, error) {
	val := &ABAMux{
		Author: Author,
		Leader: Leader,
		Epoch:  Epoch,
		Flag:   Flag,
	}
	sig, err := sigService.RequestSignature(val.Hash())
	if err != nil {
		return nil, err
	}
	val.Signature = sig
	return val, nil
}

func (v *ABAMux) Verify(committee core.Committee) bool {
	pub := committee.Name(v.Author)
	return v.Signature.Verify(pub, v.Hash())
}

func (v *ABAMux) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(v.Author)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(v.Leader)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(v.Epoch)))
	hasher.Add([]byte{v.Flag})
	return hasher.Sum256(nil)
}

func (v *ABAMux) MsgType() int {
	return ABAMuxType
}

type CoinShare struct {
	Author core.NodeID
	Leader core.NodeID
	Epoch  int64
	Share  crypto.SignatureShare
}

func NewCoinShare(Author, Leader core.NodeID, Epoch int64, sigService *crypto.SigService) (*CoinShare, error) {
	coin := &CoinShare{
		Author: Author,
		Leader: Leader,
		Epoch:  Epoch,
	}
	sig, err := sigService.RequestTsSugnature(coin.Hash())
	if err != nil {
		return nil, err
	}
	coin.Share = sig
	return coin, nil
}

func (c *CoinShare) Verify(committee core.Committee) bool {
	_ = committee.Name(c.Author)
	return c.Share.Verify(c.Hash())
}

func (c *CoinShare) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(c.Leader)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(c.Epoch)))
	return hasher.Sum256(nil)
}

func (c *CoinShare) MsgType() int {
	return CoinShareType
}

type ABAHalt struct {
	Author    core.NodeID
	Leader    core.NodeID
	Epoch     int64
	Flag      uint8
	Signature crypto.Signature
}

func NewABAHalt(Author, Leader core.NodeID, Epoch int64, Flag uint8, sigService *crypto.SigService) (*ABAHalt, error) {
	h := &ABAHalt{
		Author: Author,
		Leader: Leader,
		Epoch:  Epoch,
		Flag:   Flag,
	}
	sig, err := sigService.RequestSignature(h.Hash())
	if err != nil {
		return nil, err
	}
	h.Signature = sig
	return h, nil
}

func (h *ABAHalt) Verify(committee core.Committee) bool {
	pub := committee.Name(h.Author)
	return h.Signature.Verify(pub, h.Hash())
}

func (h *ABAHalt) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(h.Author)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(h.Leader)))
	hasher.Add(binary.BigEndian.AppendUint64(nil, uint64(h.Epoch)))
	hasher.Add([]byte{h.Flag})
	return hasher.Sum256(nil)
}

func (h *ABAHalt) MsgType() int {
	return ABAHaltType
}

const (
	ProposalType = iota
	CommitmentType
	ReadyType
	FinalType
	ElectShareType
	VoteType
	ABAValType
	ABAMuxType
	CoinShareType
	ABAHaltType
)

var DefaultMessageTypeMap = map[int]reflect.Type{
	ProposalType:   reflect.TypeOf(Proposal{}),
	CommitmentType: reflect.TypeOf(Commitment{}),
	ReadyType:      reflect.TypeOf(Ready{}),
	FinalType:      reflect.TypeOf(Final{}),
	ElectShareType: reflect.TypeOf(ElectShare{}),
	VoteType:       reflect.TypeOf(Vote{}),
	ABAValType:     reflect.TypeOf(ABAVal{}),
	ABAMuxType:     reflect.TypeOf(ABAMux{}),
	CoinShareType:  reflect.TypeOf(CoinShare{}),
	ABAHaltType:    reflect.TypeOf(ABAHalt{}),
}
