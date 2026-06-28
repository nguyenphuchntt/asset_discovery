// stages.go will describe the channel boundaries between runtime stages.
//
// Expected stages:
// - raw packets from capture.Source;
// - decoded packets from decode.Decoder;
// - observations from analyzer.Registry;
// - asset/events from asset.Manager;
// - persistence batches and stats snapshots.
//
// The file should keep backpressure behavior explicit so live capture does not
// grow memory unbounded when downstream processing is slower than input traffic.
package pipeline
