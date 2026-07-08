package storage

import (
	"context"
	"database/sql"
	_ "embed"
)

//go:embed schema.sql
var schemaSQL string

func initSchema(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, schemaSQL)
	if err != nil {
		return &schemaError{op: "init schema", err: err}
	}
	return nil
}

type schemaError struct {
	op  string
	err error
}

func (e *schemaError) Error() string {
	return "storage: " + e.op + ": " + e.err.Error()
}

func (e *schemaError) Unwrap() error { return e.err }
