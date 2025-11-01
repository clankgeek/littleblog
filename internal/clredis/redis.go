package clredis

import (
	"context"
	"time"

	"github.com/go-redis/redis/v8"
)

// Créer un store Redis personnalisé
type RedisStore struct {
	client     *redis.Client
	expiration time.Duration
}

func New(client *redis.Client) *RedisStore {
	return &RedisStore{
		client:     client,
		expiration: 5 * time.Minute,
	}
}

func (r *RedisStore) Set(id string, value string) error {
	ctx := context.Background()
	return r.client.Set(ctx, "captcha:"+id, value, r.expiration).Err()
}

func (r *RedisStore) Get(id string, clear bool) string {
	ctx := context.Background()
	key := "captcha:" + id
	val, _ := r.client.Get(ctx, key).Result()
	if clear {
		r.client.Del(ctx, key)
	}
	return val
}

func (r *RedisStore) Verify(id, answer string, clear bool) bool {
	v := r.Get(id, clear)
	return v == answer
}
