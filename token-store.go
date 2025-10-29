package oauth2_firestore

import (
	"context"
	"errors"
	"reflect"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
)

const (
	keyCode    = "Code"
	keyAccess  = "Access"
	keyRefresh = "Refresh"

	timeout = 30 * time.Second
)

// New returns a new Firestore token database.
// The provided Firestore client will never be closed.
func New(client *firestore.Client, collection string) oauth2.TokenStore {
	return NewWithTimeout(client, collection, timeout)
}

// NewWithTimeout returns a new Firestore token database.
// The provided Firestore client will never be closed and all Firestore operations will be cancelled
// if they surpass the provided timeout.
func NewWithTimeout(client *firestore.Client, collection string, timeout time.Duration) oauth2.TokenStore {
	d := &database{client: client, collection: collection, timeout: timeout}
	return &tokenStore{d: d}
}

type tokenStore struct {
	d *database
}

func (ts *tokenStore) Create(ctx context.Context, info oauth2.TokenInfo) error {
	t, err := token(info)
	if err != nil {
		return err
	}
	return ts.d.Put(ctx, t)
}

func (ts *tokenStore) RemoveByCode(ctx context.Context, code string) error {
	return ts.d.Del(ctx, keyCode, code)
}

func (ts *tokenStore) RemoveByAccess(ctx context.Context, access string) error {
	return ts.d.Del(ctx, keyAccess, access)
}

func (ts *tokenStore) RemoveByRefresh(ctx context.Context, refresh string) error {
	return ts.d.Del(ctx, keyRefresh, refresh)
}

func (ts *tokenStore) GetByCode(ctx context.Context, code string) (oauth2.TokenInfo, error) {
	return ts.d.Get(ctx, keyCode, code)
}

func (ts *tokenStore) GetByAccess(ctx context.Context, access string) (oauth2.TokenInfo, error) {
	return ts.d.Get(ctx, keyAccess, access)
}

func (ts *tokenStore) GetByRefresh(ctx context.Context, refresh string) (oauth2.TokenInfo, error) {
	return ts.d.Get(ctx, keyRefresh, refresh)
}

// ErrInvalidTokenInfo is returned whenever oauth2.TokenInfo is either nil or zero/empty.
var ErrInvalidTokenInfo = errors.New("invalid oauth2.TokenInfo")

func token(info oauth2.TokenInfo) (*models.Token, error) {
	if isNilOrZero(info) {
		return nil, ErrInvalidTokenInfo
	}
	return &models.Token{
		ClientID:            info.GetClientID(),
		UserID:              info.GetUserID(),
		RedirectURI:         info.GetRedirectURI(),
		Scope:               info.GetScope(),
		Code:                info.GetCode(),
		CodeCreateAt:        info.GetCodeCreateAt(),
		CodeExpiresIn:       info.GetCodeExpiresIn(),
		CodeChallenge:       info.GetCodeChallenge(),
		CodeChallengeMethod: string(info.GetCodeChallengeMethod()),
		Access:              info.GetAccess(),
		AccessCreateAt:      info.GetAccessCreateAt(),
		AccessExpiresIn:     info.GetAccessExpiresIn(),
		Refresh:             info.GetRefresh(),
		RefreshCreateAt:     info.GetRefreshCreateAt(),
		RefreshExpiresIn:    info.GetRefreshExpiresIn(),
	}, nil
}

func isNilOrZero(info oauth2.TokenInfo) bool {
	if info == nil {
		return true
	}
	if v := reflect.ValueOf(info); v.IsNil() {
		return true
	}
	return reflect.DeepEqual(info, info.New())
}
