// Package ui embeds the static dashboard assets so they can be served by
// internal/api without needing to ship separate files alongside the binary.
package ui

import "embed"

//go:embed static/*
var Static embed.FS
