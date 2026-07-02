// runner.go will define the main service runner used by cmd/discovery.
//
// Responsibilities:
//   - start the configured capture source, decoder workers, analyzer registry,
//     asset manager, lifecycle tracker, persister, stats collector, and API;
//   - propagate context cancellation and shutdown signals;
//   - drain channels cleanly on PCAP EOF or live shutdown;
//   - return a clear error if any required stage cannot start.
package pipeline
