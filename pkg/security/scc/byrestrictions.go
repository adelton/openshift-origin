package scc

import (
	kapi "k8s.io/kubernetes/pkg/api"
	securityapi "github.com/openshift/origin/pkg/security/apis/security"
)

// ByRestrictions is a helper to sort SCCs in order of most restrictive to least restrictive.
type ByRestrictions []*securityapi.SecurityContextConstraints

func (s ByRestrictions) Len() int {
	return len(s)
}
func (s ByRestrictions) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s ByRestrictions) Less(i, j int) bool {
	return pointValue(s[i]) < pointValue(s[j])
}

// pointValue places a value on the SCC based on the settings of the SCC that can be used
// to determine how restrictive it is.  The lower the number, the more restrictive it is.
func pointValue(constraint *securityapi.SecurityContextConstraints) int {
	points := 0

	// make sure these are always valued higher than the combination of the highest strategies
	if constraint.AllowPrivilegedContainer {
		points += 200000
	}

	// add points based on volume requests
	points += volumePointValue(constraint)

	// add points based on capabilities
	points += capabilitiesPointValue(constraint)

	// strategies in order of least restrictive to most restrictive
	switch constraint.SELinuxContext.Type {
	case securityapi.SELinuxStrategyRunAsAny:
		points += 40000
	case securityapi.SELinuxStrategyMustRunAs:
		points += 10000
	}

	switch constraint.RunAsUser.Type {
	case securityapi.RunAsUserStrategyRunAsAny:
		points += 40000
	case securityapi.RunAsUserStrategyMustRunAsNonRoot:
		points += 30000
	case securityapi.RunAsUserStrategyMustRunAsRange:
		points += 20000
	case securityapi.RunAsUserStrategyMustRunAs:
		points += 10000
	}
	return points
}

// volumePointValue returns a score based on the volumes allowed by the SCC.
// Allowing a host volume will return a score of 100000.  Allowance of anything other
// than Secret, ConfigMap, EmptyDir, DownwardAPI, Projected, and None will result in
// a score of 50000.  If the SCC only allows these trivial types, it will have a
// score of 0.
func volumePointValue(scc *securityapi.SecurityContextConstraints) int {
	hasHostVolume := false
	hasNonTrivialVolume := false
	for _, v := range scc.Volumes {
		switch v {
		case securityapi.FSTypeHostPath, securityapi.FSTypeAll:
			hasHostVolume = true
			// nothing more to do, this is the max point value
			break
		// it is easier to specifically list the trivial volumes and allow the
		// default case to be non-trivial so we don't have to worry about adding
		// volumes in the future unless they're trivial.
		case securityapi.FSTypeSecret, securityapi.FSTypeConfigMap, securityapi.FSTypeEmptyDir,
			securityapi.FSTypeDownwardAPI, securityapi.FSProjected, securityapi.FSTypeNone:
			// do nothing
		default:
			hasNonTrivialVolume = true
		}
	}

	if hasHostVolume {
		return 100000
	}
	if hasNonTrivialVolume {
		return 50000
	}
	return 0
}

// hasCap checks for needle in haystack.
func hasCap(needle kapi.Capability, haystack []kapi.Capability) bool {
	for _, c := range haystack {
		if needle == c {
			return true
		}
	}
	return false
}

// capabilitiesPointValue returns a score based on the capabilities allowed,
// added, or removed by the SCC. This allow us to prefer the more restrictive
// SCC.
func capabilitiesPointValue(scc *securityapi.SecurityContextConstraints) int {
	points := 5000
	points += 300 * len(scc.DefaultAddCapabilities)
	if hasCap(kapi.CapabilityAll, scc.AllowedCapabilities) {
		points += 4000
	} else if hasCap("ALL", scc.AllowedCapabilities) {
		points += 4000
	} else {
		points += 10 * len(scc.AllowedCapabilities)
	}
	if hasCap("ALL", scc.RequiredDropCapabilities) {
		points -= 3000
	} else {
		points -= 50 * len(scc.RequiredDropCapabilities)
	}
	if (points > 10000) {
		return 10000
	} else if (points < 0) {
		return 0
	}
	return points
}
