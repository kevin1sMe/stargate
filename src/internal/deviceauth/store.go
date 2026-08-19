package deviceauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/soulteary/stargate/src/internal/token"
)

type Store interface {
	Create(context.Context, *Grant) error
	FindByUserCode(context.Context, string) (*Grant, error)
	Resolve(context.Context, string, *token.SessionSubject, bool, time.Time) (*Grant, error)
	Poll(context.Context, string, string, time.Time) (*Grant, error)
	CreateRefresh(context.Context, string, *RefreshGrant) error
	RotateRefresh(context.Context, string, string, string, time.Time) (*RefreshGrant, error)
}

func HashSecret(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func NormalizeUserCode(code string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
}

type MemoryStore struct {
	mu       sync.Mutex
	grants   map[string]*Grant
	userCode map[string]string
	refresh  map[string]*RefreshGrant
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		grants:   make(map[string]*Grant),
		userCode: make(map[string]string),
		refresh:  make(map[string]*RefreshGrant),
	}
}

func (s *MemoryStore) Create(_ context.Context, grant *Grant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	userCode := NormalizeUserCode(grant.UserCode)
	if _, exists := s.grants[grant.DeviceCodeHash]; exists {
		return errors.New("device code collision")
	}
	if _, exists := s.userCode[userCode]; exists {
		return errors.New("user code collision")
	}
	s.grants[grant.DeviceCodeHash] = cloneGrant(grant)
	s.userCode[userCode] = grant.DeviceCodeHash
	return nil
}

func (s *MemoryStore) FindByUserCode(_ context.Context, code string) (*Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash, ok := s.userCode[NormalizeUserCode(code)]
	if !ok {
		return nil, ErrNotFound
	}
	grant, ok := s.grants[hash]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneGrant(grant), nil
}

func (s *MemoryStore) Resolve(_ context.Context, code string, subject *token.SessionSubject, approved bool, now time.Time) (*Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash, ok := s.userCode[NormalizeUserCode(code)]
	if !ok {
		return nil, ErrNotFound
	}
	grant, ok := s.grants[hash]
	if !ok {
		return nil, ErrNotFound
	}
	if !now.Before(grant.ExpiresAt) {
		return nil, ErrExpired
	}
	if grant.Status != StatusPending {
		return nil, ErrAlreadyResolved
	}
	if approved {
		copySubject := *subject
		grant.Subject = &copySubject
		grant.Status = StatusApproved
	} else {
		grant.Status = StatusDenied
	}
	return cloneGrant(grant), nil
}

func (s *MemoryStore) Poll(_ context.Context, rawDeviceCode, clientID string, now time.Time) (*Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	grant, ok := s.grants[HashSecret(rawDeviceCode)]
	if !ok || grant.ClientID != clientID {
		return nil, ErrNotFound
	}
	if !now.Before(grant.ExpiresAt) {
		return nil, ErrExpired
	}
	switch grant.Status {
	case StatusDenied:
		return nil, ErrAccessDenied
	case StatusConsumed:
		return nil, ErrAlreadyConsumed
	case StatusApproved:
		grant.Status = StatusConsumed
		return cloneGrant(grant), nil
	case StatusPending:
		if !grant.NextPollAt.IsZero() && now.Before(grant.NextPollAt) {
			grant.PollInterval += 5
			grant.NextPollAt = now.Add(time.Duration(grant.PollInterval) * time.Second)
			return nil, ErrSlowDown
		}
		grant.NextPollAt = now.Add(time.Duration(grant.PollInterval) * time.Second)
		return nil, ErrAuthorizationWait
	default:
		return nil, ErrNotFound
	}
}

func (s *MemoryStore) CreateRefresh(_ context.Context, raw string, grant *RefreshGrant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash := HashSecret(raw)
	if _, exists := s.refresh[hash]; exists {
		return errors.New("refresh token collision")
	}
	copyGrant := *grant
	s.refresh[hash] = &copyGrant
	return nil
}

func (s *MemoryStore) RotateRefresh(_ context.Context, oldRaw, newRaw, clientID string, now time.Time) (*RefreshGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	oldHash := HashSecret(oldRaw)
	grant, ok := s.refresh[oldHash]
	if !ok || grant.ClientID != clientID || !now.Before(grant.ExpiresAt) {
		return nil, ErrInvalidRefresh
	}
	delete(s.refresh, oldHash)
	copyGrant := *grant
	s.refresh[HashSecret(newRaw)] = &copyGrant
	return &copyGrant, nil
}

type RedisStore struct {
	client *redis.Client
	prefix string
}

func NewRedisStore(client *redis.Client, prefix string) *RedisStore {
	return &RedisStore{client: client, prefix: prefix}
}

func (s *RedisStore) deviceKey(hash string) string  { return s.prefix + "device:" + hash }
func (s *RedisStore) userKey(code string) string    { return s.prefix + "user:" + NormalizeUserCode(code) }
func (s *RedisStore) refreshKey(hash string) string { return s.prefix + "refresh:" + hash }

func (s *RedisStore) Create(ctx context.Context, grant *Grant) error {
	data, err := json.Marshal(grant)
	if err != nil {
		return err
	}
	ttl := time.Until(grant.ExpiresAt)
	if ttl <= 0 {
		return ErrExpired
	}
	deviceKey := s.deviceKey(grant.DeviceCodeHash)
	ok, err := s.client.SetNX(ctx, deviceKey, data, ttl).Result()
	if err != nil || !ok {
		if err != nil {
			return err
		}
		return errors.New("device code collision")
	}
	ok, err = s.client.SetNX(ctx, s.userKey(grant.UserCode), grant.DeviceCodeHash, ttl).Result()
	if err != nil || !ok {
		s.client.Del(ctx, deviceKey)
		if err != nil {
			return err
		}
		return errors.New("user code collision")
	}
	return nil
}

func (s *RedisStore) FindByUserCode(ctx context.Context, code string) (*Grant, error) {
	hash, err := s.client.Get(ctx, s.userKey(code)).Result()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.getGrant(ctx, hash)
}

func (s *RedisStore) getGrant(ctx context.Context, hash string) (*Grant, error) {
	data, err := s.client.Get(ctx, s.deviceKey(hash)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var grant Grant
	if err := json.Unmarshal(data, &grant); err != nil {
		return nil, err
	}
	return &grant, nil
}

func (s *RedisStore) Resolve(ctx context.Context, code string, subject *token.SessionSubject, approved bool, now time.Time) (*Grant, error) {
	hash, err := s.client.Get(ctx, s.userKey(code)).Result()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	key := s.deviceKey(hash)
	var resolved *Grant
	err = s.client.Watch(ctx, func(tx *redis.Tx) error {
		data, err := tx.Get(ctx, key).Bytes()
		if errors.Is(err, redis.Nil) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		var grant Grant
		if err := json.Unmarshal(data, &grant); err != nil {
			return err
		}
		if !now.Before(grant.ExpiresAt) {
			return ErrExpired
		}
		if grant.Status != StatusPending {
			return ErrAlreadyResolved
		}
		if approved {
			copySubject := *subject
			grant.Subject = &copySubject
			grant.Status = StatusApproved
		} else {
			grant.Status = StatusDenied
		}
		encoded, err := json.Marshal(&grant)
		if err != nil {
			return err
		}
		ttl := time.Until(grant.ExpiresAt)
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.Set(ctx, key, encoded, ttl)
			return nil
		})
		if err == nil {
			resolved = &grant
		}
		return err
	}, key)
	return resolved, err
}

func (s *RedisStore) Poll(ctx context.Context, rawDeviceCode, clientID string, now time.Time) (*Grant, error) {
	key := s.deviceKey(HashSecret(rawDeviceCode))
	var result *Grant
	err := s.client.Watch(ctx, func(tx *redis.Tx) error {
		data, err := tx.Get(ctx, key).Bytes()
		if errors.Is(err, redis.Nil) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		var grant Grant
		if err := json.Unmarshal(data, &grant); err != nil {
			return err
		}
		if grant.ClientID != clientID {
			return ErrNotFound
		}
		if !now.Before(grant.ExpiresAt) {
			return ErrExpired
		}
		var statusErr error
		switch grant.Status {
		case StatusDenied:
			return ErrAccessDenied
		case StatusConsumed:
			return ErrAlreadyConsumed
		case StatusApproved:
			grant.Status = StatusConsumed
			result = &grant
		case StatusPending:
			if !grant.NextPollAt.IsZero() && now.Before(grant.NextPollAt) {
				grant.PollInterval += 5
				statusErr = ErrSlowDown
			} else {
				statusErr = ErrAuthorizationWait
			}
			grant.NextPollAt = now.Add(time.Duration(grant.PollInterval) * time.Second)
		default:
			return ErrNotFound
		}
		encoded, err := json.Marshal(&grant)
		if err != nil {
			return err
		}
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.Set(ctx, key, encoded, time.Until(grant.ExpiresAt))
			return nil
		})
		if err != nil {
			return err
		}
		return statusErr
	}, key)
	return result, err
}

func (s *RedisStore) CreateRefresh(ctx context.Context, raw string, grant *RefreshGrant) error {
	data, err := json.Marshal(grant)
	if err != nil {
		return err
	}
	ttl := time.Until(grant.ExpiresAt)
	if ttl <= 0 {
		return ErrInvalidRefresh
	}
	ok, err := s.client.SetNX(ctx, s.refreshKey(HashSecret(raw)), data, ttl).Result()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("refresh token collision")
	}
	return nil
}

func (s *RedisStore) RotateRefresh(ctx context.Context, oldRaw, newRaw, clientID string, now time.Time) (*RefreshGrant, error) {
	oldKey := s.refreshKey(HashSecret(oldRaw))
	newKey := s.refreshKey(HashSecret(newRaw))
	var result *RefreshGrant
	err := s.client.Watch(ctx, func(tx *redis.Tx) error {
		data, err := tx.Get(ctx, oldKey).Bytes()
		if errors.Is(err, redis.Nil) {
			return ErrInvalidRefresh
		}
		if err != nil {
			return err
		}
		var grant RefreshGrant
		if err := json.Unmarshal(data, &grant); err != nil {
			return err
		}
		if grant.ClientID != clientID || !now.Before(grant.ExpiresAt) {
			return ErrInvalidRefresh
		}
		ttl := time.Until(grant.ExpiresAt)
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.Del(ctx, oldKey)
			pipe.Set(ctx, newKey, data, ttl)
			return nil
		})
		if err == nil {
			result = &grant
		}
		return err
	}, oldKey)
	return result, err
}

func cloneGrant(grant *Grant) *Grant {
	data, _ := json.Marshal(grant)
	var out Grant
	_ = json.Unmarshal(data, &out)
	return &out
}
