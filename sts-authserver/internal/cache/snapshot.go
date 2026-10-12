package cache

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type Loader[T any] func(context.Context) (T, error)

// Snapshot atomically replaces an immutable value loaded from an external source.
type Snapshot[T any] struct {
	loader      Loader[T]
	trigger     chan struct{}
	refreshLock chan struct{}

	mu          sync.RWMutex
	current     T
	initialized bool
}

func NewSnapshot[T any](loader Loader[T]) (*Snapshot[T], error) {
	if loader == nil {
		return nil, fmt.Errorf("snapshot loader must not be nil")
	}
	return &Snapshot[T]{
		loader:      loader,
		trigger:     make(chan struct{}, 1),
		refreshLock: make(chan struct{}, 1),
	}, nil
}

// Initialize performs the initial blocking load.
func (s *Snapshot[T]) Initialize(ctx context.Context) error {
	return s.Refresh(ctx)
}

// Current returns the latest complete snapshot.
func (s *Snapshot[T]) Current() (T, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current, s.initialized
}

// Refresh loads and atomically replaces the current snapshot. Concurrent
// refreshes are serialized so an older load cannot replace a newer value.
func (s *Snapshot[T]) Refresh(ctx context.Context) error {
	select {
	case s.refreshLock <- struct{}{}:
		defer func() { <-s.refreshLock }()
	case <-ctx.Done():
		return ctx.Err()
	}

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

// Trigger requests a refresh without blocking the caller. Multiple pending requests
// are combined because every refresh loads the complete current state.
func (s *Snapshot[T]) Trigger() {
	select {
	case s.trigger <- struct{}{}:
	default:
	}
}

// RunPeriodic refreshes on triggers and at the given fallback interval. A failed
// refresh keeps the last complete snapshot and is reported through onError.
func (s *Snapshot[T]) RunPeriodic(ctx context.Context, interval time.Duration, onError func(error)) error {
	if interval <= 0 {
		return fmt.Errorf("snapshot refresh interval must be positive")
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		case <-s.trigger:
		}

		if err := s.Refresh(ctx); err != nil && ctx.Err() == nil && onError != nil {
			onError(err)
		}
	}
}
