package asset

type MergeResult struct {
	Changed      bool
	NewIPv4s     []string
	NewIPv6s     []string
	NewHostnames []string
	NewServices  []Service
}

func mergeObservation(a *Asset, obs Observation) MergeResult {
	var r MergeResult

	changed, added4 := mergeIPMap(&a.IPv4s, obs.IPv4s, obs.ObservedAt)
	r.Changed = r.Changed || changed
	r.NewIPv4s = added4

	changed, added6 := mergeIPMap(&a.IPv6s, obs.IPv6s, obs.ObservedAt)
	r.Changed = r.Changed || changed
	r.NewIPv6s = added6

	if len(obs.Hostnames) > 0 {
		var c bool
		var added []string
		a.Hostnames, c, added = mergeStrings(a.Hostnames, obs.Hostnames...)
		r.Changed = r.Changed || c
		r.NewHostnames = added
	}
	if len(obs.Services) > 0 {
		var c bool
		var added []Service
		prev := len(a.Services)
		a.Services, c, added = mergeServices(a.Services, obs.Services...)
		r.Changed = r.Changed || c
		r.NewServices = added
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
	if a.OSVersion == "" && obs.OSVersion != "" {
		a.OSVersion = obs.OSVersion
		r.Changed = true
	}
	if a.Subnet == "" && obs.Subnet != "" {
		a.Subnet = obs.Subnet
		r.Changed = true
	}

	if obs.IsLocal && !a.IsLocal {
		a.IsLocal = true
		r.Changed = true
	}
	if obs.IsGateway && !a.IsGateway {
		a.IsGateway = true
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