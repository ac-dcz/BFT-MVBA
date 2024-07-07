package consensus

import (
	"bft/mvba/core"
	"bft/mvba/crypto"
	"bft/mvba/pool"
	"bytes"
	"encoding/gob"
	"reflect"
	"strconv"
)

const (
	PHASE_ONE_FALG int8 = iota
	PHASE_TWO_FALG
	PHASE_THREE_FALG
	PHASE_FOUR_FALG
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
	Epoch     int64
	Phase     int8
	B         *Block
	Signature crypto.Signature
}

func NewProposal(Author core.NodeID, Epoch int64, Phase int8, B *Block, sigService *crypto.SigService) (*Proposal, error) {
	p := &Proposal{
		Author: Author,
		Epoch:  Epoch,
		Phase:  Phase,
		B:      B,
	}
	sig, err := sigService.RequestSignature(p.Hash())
	if err != nil {
		return nil, err
	}
	p.Signature = sig
	return p, nil
}

func (p *Proposal) Verify(committee core.Committee) bool {
	pub := committee.Name(p.Author)
	return p.Signature.Verify(pub, p.Hash())
}

func (p *Proposal) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(p.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(p.Phase), 2))
	hasher.Add(strconv.AppendInt(nil, int64(p.Epoch), 2))
	d := p.B.Hash()
	hasher.Add(d[:])
	return hasher.Sum256(nil)
}

func (p *Proposal) MsgType() int {
	return ProposalType
}

type Vote struct {
	Author    core.NodeID
	Proposer  core.NodeID
	BlockHash crypto.Digest
	Epoch     int64
	Phase     int8
	Signature crypto.Signature
}

func NewVote(Author, Proposer core.NodeID, BlockHash crypto.Digest, Epoch int64, Phase int8, sigService *crypto.SigService) (*Vote, error) {
	vote := &Vote{
		Author:    Author,
		Proposer:  Proposer,
		BlockHash: BlockHash,
		Epoch:     Epoch,
		Phase:     Phase,
	}
	sig, err := sigService.RequestSignature(vote.Hash())
	if err != nil {
		return nil, err
	}
	vote.Signature = sig
	return vote, nil
}

func (v *Vote) Verify(committee core.Committee) bool {
	pub := committee.Name(v.Author)
	return v.Signature.Verify(pub, v.Hash())
}

func (v *Vote) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(v.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(v.Phase), 2))
	hasher.Add(strconv.AppendInt(nil, int64(v.Epoch), 2))
	hasher.Add(strconv.AppendInt(nil, int64(v.Proposer), 2))
	hasher.Add(v.BlockHash[:])
	return hasher.Sum256(nil)
}

func (v *Vote) MsgType() int {
	return VoteType
}

type Done struct {
	Author    core.NodeID
	Epoch     int64
	Signature crypto.Signature
}

func NewDone(Author core.NodeID, Epoch int64, sigService *crypto.SigService) (*Done, error) {
	d := &Done{
		Author: Author,
		Epoch:  Epoch,
	}
	sig, err := sigService.RequestSignature(d.Hash())
	if err != nil {
		return nil, err
	}
	d.Signature = sig
	return d, nil
}

func (d *Done) Verify(committee core.Committee) bool {
	pub := committee.Name(d.Author)
	return d.Signature.Verify(pub, d.Hash())
}

func (d *Done) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(d.Author), 2))
	hasher.Add(strconv.AppendInt(nil, d.Epoch, 2))
	return hasher.Sum256(nil)
}

func (d *Done) MsgType() int {
	return DoneType
}

type Skip struct {
	Author    core.NodeID
	Epoch     int64
	Signature crypto.Signature
}

func NewSkip(Author core.NodeID, Epoch int64, sigService *crypto.SigService) (*Skip, error) {
	skip := &Skip{
		Author: Author,
		Epoch:  Epoch,
	}
	sig, err := sigService.RequestSignature(skip.Hash())
	if err != nil {
		return nil, err
	}
	skip.Signature = sig
	return skip, nil
}

func (s *Skip) Verify(committee core.Committee) bool {
	pub := committee.Name(s.Author)
	return s.Signature.Verify(pub, s.Hash())
}

func (s *Skip) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, s.Epoch, 2))
	hasher.Add(strconv.AppendInt(nil, int64(s.Author), 2))
	return hasher.Sum256(nil)
}

func (s *Skip) MsgType() int {
	return SkipType
}

type ElectShare struct {
	Author   core.NodeID
	Epoch    int64
	SigShare crypto.SignatureShare
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
	e.SigShare = sig
	return e, nil
}

func (e *ElectShare) Verify(committee core.Committee) bool {
	_ = committee.Name(e.Author)
	return e.SigShare.Verify(e.Hash())
}

func (e *ElectShare) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, e.Epoch, 2))
	return hasher.Sum256(nil)
}

func (e *ElectShare) MsgType() int {
	return ElectShareType
}

type ViewChange struct {
	Author    core.NodeID
	Epoch     int64
	BlockHash *crypto.Digest //may be is nil
	IsCommit  bool
	IsLock    bool
	IsKey     bool
	Signature crypto.Signature
}

func NewViewChange(Author core.NodeID, Epoch int64, BlockHash *crypto.Digest, commit, lock, key bool, sigService *crypto.SigService) (*ViewChange, error) {
	v := &ViewChange{
		Author:    Author,
		Epoch:     Epoch,
		BlockHash: BlockHash,
		IsCommit:  commit,
		IsLock:    lock,
		IsKey:     key,
	}
	sig, err := sigService.RequestSignature(v.Hash())
	if err != nil {
		return nil, err
	}
	v.Signature = sig
	return v, nil
}

func (v *ViewChange) Verify(committee core.Committee) bool {
	pub := committee.Name(v.Author)
	return v.Signature.Verify(pub, v.Hash())
}

func (v *ViewChange) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(v.Author), 2))
	hasher.Add(strconv.AppendBool(nil, v.IsCommit))
	hasher.Add(strconv.AppendBool(nil, v.IsLock))
	hasher.Add(strconv.AppendBool(nil, v.IsKey))
	return hasher.Sum256(nil)
}

func (v *ViewChange) MsgType() int {
	return ViewChangeType
}

const (
	ProposalType = iota
	VoteType
	DoneType
	SkipType
	ElectShareType
	ViewChangeType
)

var DefaultMessageTypeMap = map[int]reflect.Type{
	ProposalType:   reflect.TypeOf(Proposal{}),
	VoteType:       reflect.TypeOf(Vote{}),
	DoneType:       reflect.TypeOf(Done{}),
	SkipType:       reflect.TypeOf(Skip{}),
	ElectShareType: reflect.TypeOf(ElectShare{}),
	ViewChangeType: reflect.TypeOf(ViewChange{}),
}
