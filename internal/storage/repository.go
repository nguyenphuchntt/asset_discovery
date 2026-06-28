// repository.go will define the storage.Repository interface.
//
// Expected responsibilities:
// - upsert asset batches;
// - upsert IP history;
// - append lifecycle/audit events;
// - save stats snapshots;
// - list/filter assets for API;
// - load persisted assets at startup.
package storage
