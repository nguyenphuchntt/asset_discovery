// wiring.go will translate config.Config into concrete implementations.
//
// It should decide:
// - FileSource versus LiveSource;
// - analyzer set enabled for minimal/full modes;
// - SQLite repository path;
// - OUI lookup source;
// - API bind address;
// - lifecycle thresholds and flush intervals.
package pipeline
