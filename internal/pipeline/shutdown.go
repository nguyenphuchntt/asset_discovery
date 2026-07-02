// shutdown.go will contain graceful shutdown coordination.
//
// It should close capture handles, stop worker goroutines, flush dirty assets,
// persist final stats/events, and close storage. It should make SIGINT/SIGTERM,
// PCAP EOF, and fatal runtime errors follow one consistent shutdown path.
package pipeline
