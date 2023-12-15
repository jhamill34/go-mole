package runner

import "context"

type Tunneler interface {
	Start(ctx context.Context)
	Stop()
}

type Mole struct {
	tunneler []Tunneler
}

func NewMole(tunneler ...Tunneler) *Mole {
	return &Mole{tunneler: tunneler}
}

func (m *Mole) Start(ctx context.Context) {
	for _, t := range m.tunneler {
		t.Start(ctx)
	}
}

func (m *Mole) Stop() {
	for _, t := range m.tunneler {
		t.Stop()
	}
}

