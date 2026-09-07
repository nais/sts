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
	}, time.Hour)
	require.NoError(t, err)
	require.NoError(t, snapshot.Initialize(t.Context()))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go snapshot.Run(ctx, nil)

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
	}, time.Millisecond)
	require.NoError(t, err)
	require.NoError(t, snapshot.Initialize(t.Context()))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go snapshot.Run(ctx, nil)

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
	}, time.Hour)
	require.NoError(t, err)
	require.NoError(t, snapshot.Initialize(t.Context()))

	errors := make(chan error, 1)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go snapshot.Run(ctx, func(err error) { errors <- err })

	fail.Store(true)
	snapshot.Trigger()
	require.ErrorIs(t, <-errors, loadErr)
	value, ok := snapshot.Current()
	require.True(t, ok)
	require.Equal(t, "initial", value)
}
