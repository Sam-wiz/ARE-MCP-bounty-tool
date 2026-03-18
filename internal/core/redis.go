package core

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisClient wraps the Redis client for task queue
type RedisClient struct {
	client *redis.Client
}

// Queue names
const (
	QueueTasks    = "hackai:tasks"
	QueueResults  = "hackai:results"
	QueueWorkers  = "hackai:workers"
	ChannelEvents = "hackai:events"
)

// NewRedisClient creates a new Redis client
func NewRedisClient(addr string) (*RedisClient, error) {
	client := redis.NewClient(&redis.Options{
		Addr:        addr,
		Password:    "",
		DB:          0,
		DialTimeout: 5 * time.Second,
	})

	// Ping to verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisClient{client: client}, nil
}

// Close closes the Redis connection
func (r *RedisClient) Close() error {
	return r.client.Close()
}

// ============================================================================
// TASK QUEUE
// ============================================================================

// EnqueueTask adds a task to the queue
func (r *RedisClient) EnqueueTask(ctx context.Context, taskJSON string) error {
	return r.client.LPush(ctx, QueueTasks, taskJSON).Err()
}

// DequeueTask removes and returns a task from the queue
func (r *RedisClient) DequeueTask(ctx context.Context, timeout time.Duration) (string, error) {
	result, err := r.client.BRPop(ctx, timeout, QueueTasks).Result()
	if err != nil {
		if err == redis.Nil {
			return "", nil
		}
		return "", err
	}

	if len(result) < 2 {
		return "", nil
	}

	return result[1], nil
}

// GetQueueLength returns the number of pending tasks
func (r *RedisClient) GetQueueLength(ctx context.Context) (int64, error) {
	return r.client.LLen(ctx, QueueTasks).Result()
}

// ============================================================================
// RESULTS
// ============================================================================

// PublishResult publishes a task result
func (r *RedisClient) PublishResult(ctx context.Context, taskID, resultJSON string) error {
	key := fmt.Sprintf("%s:%s", QueueResults, taskID)
	return r.client.Set(ctx, key, resultJSON, 24*time.Hour).Err()
}

// GetResult retrieves a task result
func (r *RedisClient) GetResult(ctx context.Context, taskID string) (string, error) {
	key := fmt.Sprintf("%s:%s", QueueResults, taskID)
	return r.client.Get(ctx, key).Result()
}

// WaitForResult waits for a task result with timeout
func (r *RedisClient) WaitForResult(ctx context.Context, taskID string, timeout time.Duration) (string, error) {
	key := fmt.Sprintf("%s:%s", QueueResults, taskID)
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		result, err := r.client.Get(ctx, key).Result()
		if err == nil {
			return result, nil
		}
		if err != redis.Nil {
			return "", err
		}

		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(100 * time.Millisecond):
			// Continue polling
		}
	}

	return "", fmt.Errorf("timeout waiting for result")
}

// ============================================================================
// WORKER STATUS
// ============================================================================

// SetWorkerStatus updates worker status
func (r *RedisClient) SetWorkerStatus(ctx context.Context, workerID, statusJSON string) error {
	key := fmt.Sprintf("%s:%s", QueueWorkers, workerID)
	return r.client.Set(ctx, key, statusJSON, 0).Err()
}

// GetWorkerStatus retrieves worker status
func (r *RedisClient) GetWorkerStatus(ctx context.Context, workerID string) (string, error) {
	key := fmt.Sprintf("%s:%s", QueueWorkers, workerID)
	return r.client.Get(ctx, key).Result()
}

// GetAllWorkerIDs returns all active worker IDs
func (r *RedisClient) GetAllWorkerIDs(ctx context.Context) ([]string, error) {
	pattern := fmt.Sprintf("%s:*", QueueWorkers)
	keys, err := r.client.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, err
	}

	// Extract IDs from keys
	ids := make([]string, len(keys))
	prefix := QueueWorkers + ":"
	for i, key := range keys {
		ids[i] = key[len(prefix):]
	}

	return ids, nil
}

// DeleteWorkerStatus removes worker status
func (r *RedisClient) DeleteWorkerStatus(ctx context.Context, workerID string) error {
	key := fmt.Sprintf("%s:%s", QueueWorkers, workerID)
	return r.client.Del(ctx, key).Err()
}

// ============================================================================
// PUB/SUB EVENTS
// ============================================================================

// PublishEvent publishes an event
func (r *RedisClient) PublishEvent(ctx context.Context, eventJSON string) error {
	return r.client.Publish(ctx, ChannelEvents, eventJSON).Err()
}

// SubscribeEvents subscribes to events
func (r *RedisClient) SubscribeEvents(ctx context.Context) *redis.PubSub {
	return r.client.Subscribe(ctx, ChannelEvents)
}

// ============================================================================
// RATE LIMITING
// ============================================================================

// CheckRateLimit checks if an action is rate limited
func (r *RedisClient) CheckRateLimit(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	rateLimitKey := fmt.Sprintf("ratelimit:%s", key)

	// Increment counter
	count, err := r.client.Incr(ctx, rateLimitKey).Result()
	if err != nil {
		return false, err
	}

	// Set expiry on first increment
	if count == 1 {
		r.client.Expire(ctx, rateLimitKey, window)
	}

	return count <= int64(limit), nil
}

// GetRateLimitRemaining gets remaining requests in window
func (r *RedisClient) GetRateLimitRemaining(ctx context.Context, key string, limit int) (int, error) {
	rateLimitKey := fmt.Sprintf("ratelimit:%s", key)

	count, err := r.client.Get(ctx, rateLimitKey).Int()
	if err == redis.Nil {
		return limit, nil
	}
	if err != nil {
		return 0, err
	}

	remaining := limit - count
	if remaining < 0 {
		remaining = 0
	}

	return remaining, nil
}

// ============================================================================
// CACHING (for future use)
// ============================================================================

// SetCache sets a cached value
func (r *RedisClient) SetCache(ctx context.Context, key string, value string, ttl time.Duration) error {
	cacheKey := fmt.Sprintf("cache:%s", key)
	return r.client.Set(ctx, cacheKey, value, ttl).Err()
}

// GetCache gets a cached value
func (r *RedisClient) GetCache(ctx context.Context, key string) (string, error) {
	cacheKey := fmt.Sprintf("cache:%s", key)
	return r.client.Get(ctx, cacheKey).Result()
}

// DeleteCache deletes a cached value
func (r *RedisClient) DeleteCache(ctx context.Context, key string) error {
	cacheKey := fmt.Sprintf("cache:%s", key)
	return r.client.Del(ctx, cacheKey).Err()
}
