package cache

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const listenerReconnectDelay = time.Second

// PostgresListener converts PostgreSQL notifications into local refresh signals.
type PostgresListener struct {
	pool       *pgxpool.Pool
	channel    string
	onNotify   func(string)
	log        *slog.Logger
	connection *pgxpool.Conn
}

func NewPostgresListener(pool *pgxpool.Pool, channel string, onNotify func(string), log *slog.Logger) *PostgresListener {
	return &PostgresListener{
		pool:     pool,
		channel:  channel,
		onNotify: onNotify,
		log:      log,
	}
}

// Connect starts listening before the initial snapshot is loaded, avoiding a gap
// between loading database state and subscribing to later changes.
func (l *PostgresListener) Connect(ctx context.Context) error {
	connection, err := l.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire PostgreSQL listener connection: %w", err)
	}
	if _, err := connection.Exec(ctx, "LISTEN "+pgx.Identifier{l.channel}.Sanitize()); err != nil {
		connection.Release()
		return fmt.Errorf("listen for PostgreSQL notifications: %w", err)
	}
	l.connection = connection
	return nil
}

func (l *PostgresListener) Close() {
	if l.connection != nil {
		l.connection.Release()
		l.connection = nil
	}
}

// Run waits for notifications and reconnects until the context is cancelled.
func (l *PostgresListener) Run(ctx context.Context) {
	defer l.Close()

	for {
		if l.connection == nil {
			if err := l.reconnect(ctx); err != nil {
				return
			}
			// A notification may have been missed while disconnected.
			l.onNotify("")
		}

		notification, err := l.connection.Conn().WaitForNotification(ctx)
		if err == nil {
			l.onNotify(notification.Payload)
			continue
		}
		if ctx.Err() != nil {
			return
		}

		l.log.Warn("PostgreSQL cache listener disconnected", "error", err)
		l.Close()
	}
}

func (l *PostgresListener) reconnect(ctx context.Context) error {
	for {
		if err := l.Connect(ctx); err == nil {
			l.log.Info("PostgreSQL cache listener reconnected")
			return nil
		} else {
			l.log.Warn("reconnect PostgreSQL cache listener", "error", err)
		}

		timer := time.NewTimer(listenerReconnectDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
