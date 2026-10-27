// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import "testing"

func TestSelfHostedEnterpriseServicesEnabled(t *testing.T) {
	tests := []struct {
		name string
		mode string
		want bool
	}{
		{name: "hosted SaaS owns the community SaaS schema", mode: "community-saas", want: false},
		{name: "self-hosted enterprise owns the enterprise schema", mode: "enterprise", want: true},
		{name: "in-vpc enterprise owns the enterprise schema", mode: "in-vpc-enterprise", want: true},
		{name: "local development keeps existing self-hosted behavior", mode: "", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", tt.mode)
			if got := selfHostedEnterpriseServicesEnabled(); got != tt.want {
				t.Fatalf("selfHostedEnterpriseServicesEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}
