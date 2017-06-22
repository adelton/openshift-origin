package scc

import (
	"testing"

	kapi "k8s.io/kubernetes/pkg/api"
	securityapi "github.com/openshift/origin/pkg/security/apis/security"
)

func TestPointValue(t *testing.T) {
	newSCC := func(priv bool, seLinuxStrategy securityapi.SELinuxContextStrategyType, userStrategy securityapi.RunAsUserStrategyType) *securityapi.SecurityContextConstraints {
		scc := &securityapi.SecurityContextConstraints{
			SELinuxContext: securityapi.SELinuxContextStrategyOptions{
				Type: seLinuxStrategy,
			},
			RunAsUser: securityapi.RunAsUserStrategyOptions{
				Type: userStrategy,
			},
		}
		if priv {
			scc.AllowPrivilegedContainer = true
		}

		return scc
	}

	seLinuxStrategies := map[securityapi.SELinuxContextStrategyType]int{
		securityapi.SELinuxStrategyRunAsAny:  40000,
		securityapi.SELinuxStrategyMustRunAs: 10000,
	}
	userStrategies := map[securityapi.RunAsUserStrategyType]int{
		securityapi.RunAsUserStrategyRunAsAny:         40000,
		securityapi.RunAsUserStrategyMustRunAsNonRoot: 30000,
		securityapi.RunAsUserStrategyMustRunAsRange:   20000,
		securityapi.RunAsUserStrategyMustRunAs:        10000,
	}

	privilegedPoints := 200000

	// run through all combos of user strategy + seLinux strategy + priv
	for userStrategy, userStrategyPoints := range userStrategies {
		for seLinuxStrategy, seLinuxStrategyPoints := range seLinuxStrategies {
			expectedPoints := 5000 + privilegedPoints + userStrategyPoints + seLinuxStrategyPoints
			scc := newSCC(true, seLinuxStrategy, userStrategy)
			actualPoints := pointValue(scc)

			if actualPoints != expectedPoints {
				t.Errorf("privileged, user: %v, seLinux %v expected %d score but got %d", userStrategy, seLinuxStrategy, expectedPoints, actualPoints)
			}

			expectedPoints = 5000 + userStrategyPoints + seLinuxStrategyPoints
			scc = newSCC(false, seLinuxStrategy, userStrategy)
			actualPoints = pointValue(scc)

			if actualPoints != expectedPoints {
				t.Errorf("non privileged, user: %v, seLinux %v expected %d score but got %d", userStrategy, seLinuxStrategy, expectedPoints, actualPoints)
			}
		}
	}

	// sanity check to ensure volume and capabilities scores are added (specific volumes
	// and capabilities scores are tested below
	scc := newSCC(false, securityapi.SELinuxStrategyMustRunAs, securityapi.RunAsUserStrategyMustRunAs)
	scc.Volumes = []securityapi.FSType{securityapi.FSTypeHostPath}
	actualPoints := pointValue(scc)
	if actualPoints != 125000 { //10000 (SELinux) + 10000 (User) + 100000 (host path volume) + 5000 capabilities
		t.Errorf("volume score was not added to the scc point value correctly, got %d!", actualPoints)
	}
}

func TestVolumePointValue(t *testing.T) {
	newSCC := func(host, nonTrivial, trivial bool) *securityapi.SecurityContextConstraints {
		volumes := []securityapi.FSType{}
		if host {
			volumes = append(volumes, securityapi.FSTypeHostPath)
		}
		if nonTrivial {
			volumes = append(volumes, securityapi.FSTypeAWSElasticBlockStore)
		}
		if trivial {
			volumes = append(volumes, securityapi.FSTypeSecret)
		}
		return &securityapi.SecurityContextConstraints{
			Volumes: volumes,
		}
	}

	allowAllSCC := &securityapi.SecurityContextConstraints{
		Volumes: []securityapi.FSType{securityapi.FSTypeAll},
	}
	nilVolumeSCC := &securityapi.SecurityContextConstraints{}

	tests := map[string]struct {
		scc            *securityapi.SecurityContextConstraints
		expectedPoints int
	}{
		"all volumes": {
			scc:            allowAllSCC,
			expectedPoints: 100000,
		},
		"host volume": {
			scc:            newSCC(true, false, false),
			expectedPoints: 100000,
		},
		"host volume and non trivial volumes": {
			scc:            newSCC(true, true, false),
			expectedPoints: 100000,
		},
		"host volume, non trivial, and trivial": {
			scc:            newSCC(true, true, true),
			expectedPoints: 100000,
		},
		"non trivial": {
			scc:            newSCC(false, true, false),
			expectedPoints: 50000,
		},
		"non trivial and trivial": {
			scc:            newSCC(false, true, true),
			expectedPoints: 50000,
		},
		"trivial": {
			scc:            newSCC(false, false, true),
			expectedPoints: 0,
		},
		"trivial - secret": {
			scc: &securityapi.SecurityContextConstraints{
				Volumes: []securityapi.FSType{securityapi.FSTypeSecret},
			},
			expectedPoints: 0,
		},
		"trivial - configMap": {
			scc: &securityapi.SecurityContextConstraints{
				Volumes: []securityapi.FSType{securityapi.FSTypeConfigMap},
			},
			expectedPoints: 0,
		},
		"trivial - emptyDir": {
			scc: &securityapi.SecurityContextConstraints{
				Volumes: []securityapi.FSType{securityapi.FSTypeEmptyDir},
			},
			expectedPoints: 0,
		},
		"trivial - downwardAPI": {
			scc: &securityapi.SecurityContextConstraints{
				Volumes: []securityapi.FSType{securityapi.FSTypeDownwardAPI},
			},
			expectedPoints: 0,
		},
		"trivial - projected": {
			scc: &securityapi.SecurityContextConstraints{
				Volumes: []securityapi.FSType{securityapi.FSProjected},
			},
			expectedPoints: 0,
		},
		"trivial - none": {
			scc: &securityapi.SecurityContextConstraints{
				Volumes: []securityapi.FSType{securityapi.FSTypeNone},
			},
			expectedPoints: 0,
		},
		"no volumes allowed": {
			scc:            newSCC(false, false, false),
			expectedPoints: 0,
		},
		"nil volumes": {
			scc:            nilVolumeSCC,
			expectedPoints: 0,
		},
	}
	for k, v := range tests {
		actualPoints := volumePointValue(v.scc)
		if actualPoints != v.expectedPoints {
			t.Errorf("%s expected %d volume score but got %d", k, v.expectedPoints, actualPoints)
		}
	}
}

func TestCapabilitiesPointValue(t *testing.T) {
	newSCC := func(def []kapi.Capability, allow []kapi.Capability, drop []kapi.Capability) *securityapi.SecurityContextConstraints {
		return &securityapi.SecurityContextConstraints{
			DefaultAddCapabilities: def,
			AllowedCapabilities: allow,
			RequiredDropCapabilities: drop,
		}
	}

	tests := map[string]struct {
		defaultAdd     []kapi.Capability
		allowed        []kapi.Capability
		requiredDrop   []kapi.Capability
		expectedPoints int
	}{
		"nothing specified": {
			defaultAdd:     nil,
			allowed:        nil,
			requiredDrop:   nil,
			expectedPoints: 5000,
		},
		"default": {
			defaultAdd:     []kapi.Capability{"KILL", "MKNOD"},
			allowed:        nil,
			requiredDrop:   nil,
			expectedPoints: 5600,
		},
		"allow": {
			defaultAdd:     nil,
			allowed:        []kapi.Capability{"KILL", "MKNOD"},
			requiredDrop:   nil,
			expectedPoints: 5020,
		},
		"allow star": {
			defaultAdd:     nil,
			allowed:        []kapi.Capability{"*"},
			requiredDrop:   nil,
			expectedPoints: 9000,
		},
		"allow all": {
			defaultAdd:     nil,
			allowed:        []kapi.Capability{"ALL"},
			requiredDrop:   nil,
			expectedPoints: 9000,
		},
		"drop": {
			defaultAdd:     nil,
			allowed:        nil,
			requiredDrop:   []kapi.Capability{"KILL", "MKNOD"},
			expectedPoints: 4900,
		},
		"drop all": {
			defaultAdd:     nil,
			allowed:        nil,
			requiredDrop:   []kapi.Capability{"ALL"},
			expectedPoints: 2000,
		},
		"mixture": {
			defaultAdd:     []kapi.Capability{"SETUID", "SETGID"},
			allowed:        []kapi.Capability{"*"},
			requiredDrop:   []kapi.Capability{"SYS_CHROOT"},
			expectedPoints: 9550,
		},
	}
	for k, v := range tests {
		scc := newSCC(v.defaultAdd, v.allowed, v.requiredDrop)
		actualPoints := capabilitiesPointValue(scc)
		if actualPoints != v.expectedPoints {
			t.Errorf("%s expected %d capability score but got %d", k, v.expectedPoints, actualPoints)
		}
	}
}
