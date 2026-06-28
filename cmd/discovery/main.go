package main

import (
	"errors"
	"fmt"
	"os"

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
	cfg, err := config.Parse(args)
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

	fileSource, err := capture.NewFileSource(cfg.PCAPPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Cannot open PCAP file!")
		return err
	}
	defer fileSource.Close()

	decoder := decode.NewDecoder()
	for packet := range fileSource.Packets() {
		decodedPacket, ok := decoder.Decode(packet)
		if ok {
			fmt.Print(decodedPacket, "\n")
		}
	}

	logger.Info("finished!")
	return nil
}

