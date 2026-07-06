package capture

import "errors"

var (
	ErrSourceAlreadyRun = errors.New("capture: source already run")
	ErrOutputChannelNil = errors.New("capture: output channel is nil")
	ErrNoSources = errors.New("capture: manager requires at least one source")
	ErrInvalidPath = errors.New("capture: file path is empty")
	ErrInvalidInterface = errors.New("capture: interface is empty")
	ErrInvalidBPFExpr = errors.New("capture: BPF expression invalid")
	ErrInterfaceNotFound = errors.New("capture: interface not found")
	ErrNoBPFExpression = errors.New("capture: BPF expression is empty")
)