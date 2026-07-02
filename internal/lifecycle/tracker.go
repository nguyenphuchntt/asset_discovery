// tracker.go will implement the periodic lifecycle scanner.
//
// Responsibilities:
// - run on a configurable interval;
// - compare injected clock time with asset LastSeen;
// - mark stale online assets as offline;
// - mark newly seen offline assets as online when manager receives evidence;
// - emit status change events without sleeping in unit tests.
package lifecycle
