package capture

import (
	"fmt"
	"strings"
	"sync"

	"github.com/google/gopacket/pcap"
)

type BPF struct {
	mu   sync.RWMutex
	expr string
}

func CompileBPF(expr string) (*BPF, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return &BPF{expr: ""}, nil
	}
	return &BPF{expr: expr}, nil
}

func (b *BPF) Expr() string {
	if b == nil {
		return ""
	}
	b.mu.RLock() // avoid Replace() change value at the same time
	defer b.mu.RUnlock()
	return b.expr
}

func (b *BPF) Apply(h *pcap.Handle) error {
	if b == nil || h == nil {
		return nil
	}
	b.mu.RLock()
	expr := b.expr
	b.mu.RUnlock()

	if expr == "" {
		return nil
	}
	if err := h.SetBPFFilter(expr); err != nil {
		return fmt.Errorf("%w %q: %v", ErrInvalidBPFExpr, expr, err)
	}
	return nil
}

func (b *BPF) Replace(expr string, handles []*pcap.Handle) error {
	expr = strings.TrimSpace(expr)
	if expr == "" && b != nil && b.Expr() != "" {
		return fmt.Errorf("%w", ErrNoBPFExpression)
	}
	b.mu.Lock()
	b.expr = expr
	b.mu.Unlock()
	var firstErr error
	for _, h := range handles {
		if h == nil {
			continue
		}
		if err := h.SetBPFFilter(expr); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%w %q: %v", ErrInvalidBPFExpr, expr, err)
			}
		}
	}
	return firstErr
}