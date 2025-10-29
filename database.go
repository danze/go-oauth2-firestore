package oauth2_firestore

import (
	"context"
	"errors"
	"sync"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/go-oauth2/oauth2/v4/models"
	"google.golang.org/api/iterator"
)

var ErrTokenNotFound = errors.New("token not found")

type database struct {
	mu         sync.Mutex
	client     *firestore.Client
	collection string        // Top-level Firestore collection name.
	timeout    time.Duration // Timeout for Firestore operations.
}

func (d *database) Put(ctx context.Context, token *models.Token) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	_, _, err := d.client.Collection(d.collection).Add(ctx, token)
	return err
}

func (d *database) Get(ctx context.Context, key string, val interface{}) (*models.Token, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	iter := d.client.Collection(d.collection).Where(key, "==", val).Limit(1).Documents(ctx)
	defer iter.Stop()
	doc, err := iter.Next()
	if err != nil {
		if errors.Is(err, iterator.Done) {
			return nil, ErrTokenNotFound
		}
		return nil, err
	}
	info := &models.Token{}
	err = doc.DataTo(info)
	return info, err
}

func (d *database) Del(ctx context.Context, key string, val interface{}) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	return d.client.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		query := d.client.Collection(d.collection).Where(key, "==", val).Limit(1)
		iter := tx.Documents(query)
		defer iter.Stop()
		doc, err := iter.Next()
		if err != nil {
			if errors.Is(err, iterator.Done) {
				// Document does not exist
				return nil
			}
			return err
		}
		return tx.Delete(doc.Ref)
	})
}
