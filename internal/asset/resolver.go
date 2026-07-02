// resolver.go will contain asset identity resolution policy.
//
// The resolver should decide which existing asset an Observation belongs to.
// It should avoid putting merge decisions inside analyzers or Observation.
// Initial policy can key by MAC; later policy can correlate DUID, IPv6
// link-local, hostnames, and service fingerprints with confidence rules.
package asset
