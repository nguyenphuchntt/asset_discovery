// flow.go will derive internal asset activity from TCP/UDP flow metadata.
//
// It should help lifecycle and stats by recording packet/byte activity, ports,
// and direction hints. It should not parse application payloads by default;
// deeper parsing belongs only in explicit local-discovery analyzers.
package analyzer
