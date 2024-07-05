package core

import "bft/mvba/crypto"

const (
	MVBA = iota
	SMVBA
	VABA
	PARMVBA
)

type Parameters struct {
	SyncTimeout   int  `json:"sync_timeout"`
	NetwrokDelay  int  `json:"network_delay"`
	MinBlockDelay int  `json:"min_block_delay"`
	DDos          bool `json:"ddos"`
	Faults        int  `json:"faults"`
	RetryDelay    int  `json:"retry_delay"`
	Protocol      int  `json:"protocol"`
}

var DefaultParameters = Parameters{
	SyncTimeout:   500,
	NetwrokDelay:  2_000,
	MinBlockDelay: 0,
	DDos:          false,
	Faults:        0,
	RetryDelay:    5_000,
}

type NodeID int

const NONE NodeID = -1

type Authority struct {
	Name crypto.PublickKey `json:"name"`
	Id   NodeID            `json:"node_id"`
	Addr string            `json:"addr"`
}

type Committee struct {
	Authorities map[NodeID]Authority `json:"authorities"`
}

func (c Committee) ID(name crypto.PublickKey) NodeID {
	for id, authority := range c.Authorities {
		if authority.Name.Pubkey.Equal(name.Pubkey) {
			return id
		}
	}
	return NONE
}

func (c Committee) Size() int {
	return len(c.Authorities)
}

func (c Committee) Name(id NodeID) crypto.PublickKey {
	a := c.Authorities[id]
	return a.Name
}

func (c Committee) Address(id NodeID) string {
	a := c.Authorities[id]
	return a.Addr
}

func (c Committee) BroadCast(id NodeID) []string {
	addrs := make([]string, 0)
	for nodeid, a := range c.Authorities {
		if nodeid != id {
			addrs = append(addrs, a.Addr)
		}
	}
	return addrs
}

// HightThreshold 2f+1
func (c Committee) HightThreshold() int {
	n := len(c.Authorities)
	return 2*((n-1)/3) + 1
}

// LowThreshold f+1
func (c Committee) LowThreshold() int {
	n := len(c.Authorities)
	return (n-1)/3 + 1
}

const (
	HightTH int = iota
	LowTH
)
