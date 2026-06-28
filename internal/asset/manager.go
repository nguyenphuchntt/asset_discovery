// manager.go will own in-memory asset state and merge behavior.
//
// Responsibilities:
// - apply valid Observations;
// - resolve identity and upsert assets;
// - update FirstSeen/LastSeen and online status;
// - emit lifecycle/audit events;
// - expose read-only snapshots for persistence, API, and CLI output.
package asset
