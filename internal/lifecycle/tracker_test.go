// tracker_test.go will verify online/offline transitions with a fake clock.
//
// Tests should not use time.Sleep. They should assert emitted events and dirty
// asset state after threshold crossings.
package lifecycle
