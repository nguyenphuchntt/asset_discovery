package storage

import (
	"context"
	"database/sql"
	_ "embed"
)

var schemaSQL string
func initSchema(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, schemaSQL); err != nil {
		return fmtExecContext("init schema", err)
	}
	return nil
}

func fmtExecContext(op string, err error) error {
	if err == nil {
		return nil
	}
	return &schemaError{op: op, err: err}
}

type schemaError struct {
	op  string
	err error
}

func (e *schemaError) Error() string {
	return "storage: " + e.op + ": " + e.err.Error()
}

func (e *schemaError) Unwrap() error { return e.err }