package scc

import (
	kapi "k8s.io/kubernetes/pkg/api"
)

// ByRestrictions is a helper to sort SCCs in order of most restrictive to least restrictive.
type ByRestrictions []*kapi.SecurityContextConstraints

func (s ByRestrictions) Len() int {
	return len(s)
}
func (s ByRestrictions) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s ByRestrictions) Less(i, j int) bool {
	return pointValue(s[i]) < pointValue(s[j])
}

// pointValue places a value on the SCC based on the settings of the SCC that can be used
// to determine how restrictive it is.  The lower the number, the more restrictive it is.
func pointValue(constraint *kapi.SecurityContextConstraints) int {
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
	case kapi.SELinuxStrategyRunAsAny:
		points += 40000
	case kapi.SELinuxStrategyMustRunAs:
		points += 10000
	}

	switch constraint.RunAsUser.Type {
	case kapi.RunAsUserStrategyRunAsAny:
		points += 40000
	case kapi.RunAsUserStrategyMustRunAsNonRoot:
		points += 30000
	case kapi.RunAsUserStrategyMustRunAsRange:
		points += 20000
	case kapi.RunAsUserStrategyMustRunAs:
		points += 10000
	}
	return points
}

// volumePointValue returns a score based on the volumes allowed by the SCC.
// Allowing a host volume will return a score of 10000.  Allowance of anything other
// than Secret, ConfigMap, EmptyDir, DownwardAPI, Projected, and None will result in
// a score of 5000.  If the SCC only allows these trivial types, it will have a
// score of 0.
func volumePointValue(scc *kapi.SecurityContextConstraints) int {
	hasHostVolume := false
	hasNonTrivialVolume := false
	for _, v := range scc.Volumes {
		switch v {
		case kapi.FSTypeHostPath, kapi.FSTypeAll:
			hasHostVolume = true
			// nothing more to do, this is the max point value
			break
		// it is easier to specifically list the trivial volumes and allow the
		// default case to be non-trivial so we don't have to worry about adding
		// volumes in the future unless they're trivial.
		case kapi.FSTypeSecret, kapi.FSTypeConfigMap, kapi.FSTypeEmptyDir,
			kapi.FSTypeDownwardAPI, kapi.FSProjected, kapi.FSTypeNone:
			// do nothing
		default:
			hasNonTrivialVolume = true
		}
	}

	if hasHostVolume {
		return 10000
	}
	if hasNonTrivialVolume {
		return 5000
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
// added, or removed by the SCC.
func capabilitiesPointValue(scc *kapi.SecurityContextConstraints) int {
	points := 500
	points += 30 * len(scc.DefaultAddCapabilities)
	if hasCap(kapi.CapabilityAll, scc.AllowedCapabilities) {
		points += 300
	} else {
		points += 10 * len(scc.AllowedCapabilities)
	}
	points -= 50 * len(scc.RequiredDropCapabilities)
	if (points > 1000) {
		return 1000
	} else if (points < 0) {
		return 0
	} else {
		return points
	}
}
