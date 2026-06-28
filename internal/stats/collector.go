// collector.go will provide the main stats collection API.
//
// Expected counters:
// - packets received/dropped/decoded/ignored;
// - packets and bytes by protocol;
// - observations created/rejected;
// - assets created/updated;
// - lifecycle transitions;
// - DB flush counts/errors;
// - API request counts/errors.
package stats
