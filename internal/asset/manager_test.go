// manager_test.go will test asset merge and lifecycle-facing behavior.
//
// Planned cases:
// - new asset creation;
// - repeated sightings update LastSeen only forward;
// - multiple IPs per asset;
// - hostname/vendor/source merge rules;
// - conflict handling and dirty tracking.
package asset
