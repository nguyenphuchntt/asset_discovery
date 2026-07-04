package asset

func mergeObservation(a *Asset, obs Observation) bool {
	changed := false
	var c bool

	if mergeIPMap(&a.IPv4s, obs.IPv4s, obs.ObservedAt) {
		changed = true
	}
	if mergeIPMap(&a.IPv6s, obs.IPv6s, obs.ObservedAt) {
		changed = true
	}

	if len(obs.Hostnames) > 0 {
		a.Hostnames, c = mergeStrings(a.Hostnames, obs.Hostnames...)
		changed = changed || c
	}
	if len(obs.Services) > 0 {
		prev := len(a.Services)
		a.Services, c = mergeServices(a.Services, obs.Services...)
		changed = changed || c
		if len(a.Services) > prev {
			changed = true
		}
	}

	if a.MACVendor == "" && obs.MACVendor != "" {
		a.MACVendor = obs.MACVendor
		changed = true
	}
	if a.DeviceType == "" && obs.DeviceType != "" {
		a.DeviceType = obs.DeviceType
		changed = true
	}
	if a.Model == "" && obs.Model != "" {
		a.Model = obs.Model
		changed = true
	}
	if a.OS == "" && obs.OS != "" {
		a.OS = obs.OS
		changed = true
	}
	if a.OSVersion == "" && obs.OSVersion != "" {
		a.OSVersion = obs.OSVersion
		changed = true
	}
	if a.Subnet == "" && obs.Subnet != "" {
		a.Subnet = obs.Subnet
		changed = true
	}

	if obs.IsLocal && !a.IsLocal {
		a.IsLocal = true
		changed = true
	}
	if obs.IsGateway && !a.IsGateway {
		a.IsGateway = true
		changed = true
	}

	if mergeExtras(&a.Extra, obs.Extra) {
		changed = true
	}

	if touchTimestamps(a, obs.ObservedAt) {
		changed = true
	}
	a.SeenCount++
	if !changed {
		changed = a.SeenCount == 1
	}
	return changed
}