// batch.go will define batch sizing and grouping behavior for persistence.
//
// It should keep write frequency configurable so small demos flush quickly
// while high-volume captures avoid excessive SQLite transactions.
package persist
