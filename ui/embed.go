// Package ui embeds the static dashboard assets so they can be served by
// internal/api without needing to ship separate files alongside the binary.
package ui

import "embed"

// FS is an alias for embed.FS to make the embed.FS type wrappable in function
// signatures from other packages without importing embed directly.
type FS = embed.FS

//go:embed static/*

// Static is the FS containing dashboard assets.
var Static embed.FS
