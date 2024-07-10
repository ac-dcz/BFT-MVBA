package consensus

import (
	"bft/mvba/core"
	"bft/mvba/crypto"
	"bft/mvba/pool"
	"bft/mvba/store"
)

type Core struct {
	Name       core.NodeID
	Committee  core.Committee
	Parameters core.Parameters
	SigService *crypto.SigService
	Store      *store.Store
	TxPool     *pool.Pool
	Transimtor *core.Transmitor
	CallBack   chan struct{}
}

func NewCore(
	name core.NodeID,
	committee core.Committee,
	parameters core.Parameters,
	SigService *crypto.SigService,
	Store *store.Store,
	TxPool *pool.Pool,
	Transimtor *core.Transmitor,
) *Core {
	core := &Core{
		Name:       name,
		Committee:  committee,
		Parameters: parameters,
		SigService: SigService,
		Store:      Store,
		TxPool:     TxPool,
		Transimtor: Transimtor,
	}

	return core
}
