package cache

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSnapshotRefreshesWhenTriggered(t *testing.T) {
	var loaded atomic.Int64
	snapshot, err := NewSnapshot(func(context.Context) (int64, error) {
		return loaded.Add(1), nil
	})
	require.NoError(t, err)
	require.NoError(t, snapshot.Initialize(t.Context()))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		_ = snapshot.RunPeriodic(ctx, time.Hour, nil)
	}()

	snapshot.Trigger()
	require.Eventually(t, func() bool {
		value, ok := snapshot.Current()
		return ok && value == 2
	}, time.Second, time.Millisecond)
}

func TestSnapshotRefreshesPeriodically(t *testing.T) {
	var loaded atomic.Int64
	snapshot, err := NewSnapshot(func(context.Context) (int64, error) {
		return loaded.Add(1), nil
	})
	require.NoError(t, err)
	require.NoError(t, snapshot.Initialize(t.Context()))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		_ = snapshot.RunPeriodic(ctx, time.Millisecond, nil)
	}()

	require.Eventually(t, func() bool {
		value, ok := snapshot.Current()
		return ok && value > 1
	}, time.Second, time.Millisecond)
}

func TestSnapshotKeepsCurrentValueWhenRefreshFails(t *testing.T) {
	loadErr := errors.New("load failed")
	var fail atomic.Bool
	snapshot, err := NewSnapshot(func(context.Context) (string, error) {
		if fail.Load() {
			return "", loadErr
		}
		return "initial", nil
	})
	require.NoError(t, err)
	require.NoError(t, snapshot.Initialize(t.Context()))

	errors := make(chan error, 1)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		_ = snapshot.RunPeriodic(ctx, time.Hour, func(err error) { errors <- err })
	}()

	fail.Store(true)
	snapshot.Trigger()
	require.ErrorIs(t, <-errors, loadErr)
	value, ok := snapshot.Current()
	require.True(t, ok)
	require.Equal(t, "initial", value)
}

func TestSnapshotSerializesRefreshes(t *testing.T) {
	var calls atomic.Int64
	started := make(chan struct{}, 2)
	release := make(chan struct{}, 2)
	snapshot, err := NewSnapshot(func(context.Context) (int64, error) {
		call := calls.Add(1)
		if call == 1 {
			return call, nil
		}
		started <- struct{}{}
		<-release
		return call, nil
	})
	require.NoError(t, err)
	require.NoError(t, snapshot.Initialize(t.Context()))

	errs := make(chan error, 2)
	go func() { errs <- snapshot.Refresh(t.Context()) }()
	<-started
	go func() { errs <- snapshot.Refresh(t.Context()) }()

	select {
	case <-started:
		t.Fatal("concurrent snapshot loaders were running")
	case <-time.After(20 * time.Millisecond):
	}

	release <- struct{}{}
	<-started
	release <- struct{}{}
	require.NoError(t, <-errs)
	require.NoError(t, <-errs)
}

func TestSnapshotRefreshWaitRespectsContext(t *testing.T) {
	var calls atomic.Int64
	started := make(chan struct{})
	release := make(chan struct{})
	snapshot, err := NewSnapshot(func(context.Context) (int64, error) {
		call := calls.Add(1)
		if call > 1 {
			close(started)
			<-release
		}
		return call, nil
	})
	require.NoError(t, err)
	require.NoError(t, snapshot.Initialize(t.Context()))

	first := make(chan error, 1)
	go func() { first <- snapshot.Refresh(t.Context()) }()
	<-started

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, snapshot.Refresh(ctx), context.Canceled)
	require.EqualValues(t, 2, calls.Load())

	close(release)
	require.NoError(t, <-first)
}

func TestSnapshotRejectsInvalidRefreshInterval(t *testing.T) {
	snapshot, err := NewSnapshot(func(context.Context) (string, error) {
		return "value", nil
	})
	require.NoError(t, err)
	require.EqualError(t, snapshot.RunPeriodic(t.Context(), 0, nil), "snapshot refresh interval must be positive")
}
