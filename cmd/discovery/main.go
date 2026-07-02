package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"passivediscovery/internal/analyzer"
	"passivediscovery/internal/capture"
	"passivediscovery/internal/config"
	"passivediscovery/internal/decode"
	internallog "passivediscovery/internal/log"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg, err := config.Parse(args, os.Getenv)
	if errors.Is(err, config.ErrHelp) {
		fmt.Print(config.Usage())
		return nil
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, config.Usage())
		return err
	}
	logger, err := internallog.NewLogger(cfg.LogLevel)
	if err != nil {
		fmt.Print(config.Usage())
		return err
	}

	if cfg.Mode == config.ModeLive {
		return errors.New("live capture is not implemented in this baseline")
	}

	fileSource, err := capture.NewFileSource(cfg.PCAPPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Cannot open PCAP file!")
		return err
	}
	defer fileSource.Close()

	rawPackets := make(chan capture.RawPacket, cfg.QueueSize)
	sourceErr := make(chan error, 1)
	go func() {
		defer close(rawPackets)
		sourceErr <- fileSource.Run(context.Background(), rawPackets)
	}()

	decoder := decode.NewDecoder()
	registry := analyzer.DefaultMinimalRegistry()
	for rawPacket := range rawPackets {
		decodedPacket, ok := decoder.Decode(rawPacket.Packet)
		if !ok {
			continue
		}

		observations := registry.Analyze(decodedPacket)
		for _, observation := range observations {
			fmt.Printf("%+v\n", observation)
		}
	}
	if err := <-sourceErr; err != nil {
		return err
	}

	logger.Info("finished!")
	return nil
}
