// clock.go will define the Clock abstraction for deterministic lifecycle tests.
//
// Production should use a real clock. Tests can inject a fake clock so online
// to offline transitions can be verified without time.Sleep.
package lifecycle
