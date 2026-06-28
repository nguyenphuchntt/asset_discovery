// persister.go will implement periodic and final persistence flushes.
//
// Responsibilities:
// - collect dirty asset snapshots and pending events;
// - write them to storage.Repository in batches;
// - track flush success/failure in stats;
// - flush one final time during graceful shutdown.
package persist
