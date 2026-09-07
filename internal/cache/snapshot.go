package cache

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type Loader[T any] func(context.Context) (T, error)

// Snapshot periodically replaces an immutable value loaded from an external source.
// Trigger coalesces refresh requests, which makes it suitable for database notifications.
type Snapshot[T any] struct {
	loader   Loader[T]
	interval time.Duration
	trigger  chan struct{}

	mu          sync.RWMutex
	current     T
	initialized bool
}

func NewSnapshot[T any](loader Loader[T], interval time.Duration) (*Snapshot[T], error) {
	if loader == nil {
		return nil, fmt.Errorf("snapshot loader must not be nil")
	}
	if interval <= 0 {
		return nil, fmt.Errorf("snapshot refresh interval must be positive")
	}
	return &Snapshot[T]{
		loader:   loader,
		interval: interval,
		trigger:  make(chan struct{}, 1),
	}, nil
}

// Initialize performs the initial blocking load.
func (s *Snapshot[T]) Initialize(ctx context.Context) error {
	return s.refresh(ctx)
}

// Current returns the latest complete snapshot.
func (s *Snapshot[T]) Current() (T, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current, s.initialized
}

// Trigger requests a refresh without blocking the caller. Multiple pending requests
// are combined because every refresh loads the complete current state.
func (s *Snapshot[T]) Trigger() {
	select {
	case s.trigger <- struct{}{}:
	default:
	}
}

// Run refreshes on notifications and at the configured fallback interval. A failed
// refresh keeps the last complete snapshot and is reported through onError.
func (s *Snapshot[T]) Run(ctx context.Context, onError func(error)) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-s.trigger:
		}

		if err := s.refresh(ctx); err != nil && ctx.Err() == nil && onError != nil {
			onError(err)
		}
	}
}

func (s *Snapshot[T]) refresh(ctx context.Context) error {
	value, err := s.loader(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.current = value
	s.initialized = true
	s.mu.Unlock()
	return nil
}
