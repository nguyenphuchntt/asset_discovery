package asset

type MergeResult struct {
	Changed bool
}

func mergeObservation(a *Asset, obs Observation) MergeResult {
	var r MergeResult

	mergeIPMap(&a.IPv4s, obs.IPv4s, obs.ObservedAt)
	mergeIPMap(&a.IPv6s, obs.IPv6s, obs.ObservedAt)

	if len(obs.Hostnames) > 0 {
		var c bool
		a.Hostnames, c, _ = mergeStrings(a.Hostnames, obs.Hostnames...)
		r.Changed = r.Changed || c
	}
	if len(obs.Services) > 0 {
		var c bool
		prev := len(a.Services)
		a.Services, c, _ = mergeServices(a.Services, obs.Services...)
		r.Changed = r.Changed || c
		if len(a.Services) > prev {
			r.Changed = true
		}
	}

	if a.MACVendor == "" && obs.MACVendor != "" {
		a.MACVendor = obs.MACVendor
		r.Changed = true
	}
	if a.DeviceType == "" && obs.DeviceType != "" {
		a.DeviceType = obs.DeviceType
		r.Changed = true
	}
	if a.Model == "" && obs.Model != "" {
		a.Model = obs.Model
		r.Changed = true
	}
	if a.OS == "" && obs.OS != "" {
		a.OS = obs.OS
		r.Changed = true
	}

	if mergeExtras(&a.Extra, obs.Extra) {
		r.Changed = true
	}

	if touchTimestamps(a, obs.ObservedAt) {
		r.Changed = true
	}
	a.SeenCount++
	if !r.Changed {
		r.Changed = a.SeenCount == 1
	}
	return r
}
