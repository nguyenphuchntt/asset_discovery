// env.go will load environment variable overrides for container deployments.
//
// CLI flags should remain the source of truth, with env vars filling defaults
// for Docker Compose and non-interactive runtime environments.
package config
