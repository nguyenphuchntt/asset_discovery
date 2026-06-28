// model.go will define the core Asset domain model.
//
// Asset state should represent merged passive evidence over time: identifiers,
// IP history, hostnames, vendor hints, sources/protocols, first seen, last seen,
// lifecycle status, and conflict markers. It should not store raw packets by
// default.
package asset
