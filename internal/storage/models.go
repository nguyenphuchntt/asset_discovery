// models.go will hold storage-facing row structs and conversion notes.
//
// Domain models should live in internal/asset. Storage row shapes can differ
// from domain shapes, especially for time encoding, nullable fields, and
// denormalized counters.
package storage
