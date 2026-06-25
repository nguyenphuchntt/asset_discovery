package main

import (
	"errors"
	"fmt"
	"os"

	"passivediscovery/internal/config"
	internallog "passivediscovery/internal/log"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg, err := config.Parse(args)
	if errors.Is(err, config.ErrHelp) {
		fmt.Print(config.Usage())
		return nil
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, config.Usage())
		return err
	}

	logger, err := internallog.New(cfg.LogLevel)
	if err != nil {
		return err
	}

	logger.Info(
		"config parsed successfully",
		"pcap", cfg.PCAPPath,
		"log_level", cfg.LogLevel,
		"bpf", cfg.BPF,
	)

	return nil
}
