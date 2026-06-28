// snapshot.go will define read-only stats data returned by API and CLI output.
//
// Snapshot values should be safe to marshal to JSON and should not expose
// mutable internal counter storage.
package stats
