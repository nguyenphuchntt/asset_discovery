// sqlite.go will implement Repository with SQLite.
//
// It should use transactions for batch asset/IP/event writes, handle schema
// initialization, normalize time storage, and keep SQL details out of API and
// asset packages.
package storage
