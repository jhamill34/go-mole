package tunnels

import (
	"context"
)

type BastionService interface {
	GetBastion(ctx context.Context) (*BastionEntity, error)
	PushKey(ctx context.Context, bastion *BastionEntity, pub string) error
}

type EndpointProvider interface {
	GetEndpoint(ctx context.Context) (*EndpointInfo, error)
}

type KeyProvider interface {
	RetireveKey() ([]byte, []byte)
}
