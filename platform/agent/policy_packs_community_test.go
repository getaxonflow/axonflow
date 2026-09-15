//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"strings"
	"testing"
)

// The packs are Enterprise add-ons and a Community image carries none, so a
// Community process refuses any value of the variable rather than booting
// with a pack it was told to install silently absent.
func TestACommunityBuildRefusesToInstallAPolicyPack(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "")
	t.Setenv(EnvPolicyPacks, "")
	if packs, err := loadInstalledPolicyPacks(); err != nil || packs != nil {
		t.Fatalf("unset: loadInstalledPolicyPacks() = %v, %v; want nothing (the positive control)", packs, err)
	}
	t.Setenv(EnvPolicyPacks, "fincrime")
	_, err := loadInstalledPolicyPacks()
	if err == nil || !strings.Contains(err.Error(), "community build") || !strings.Contains(err.Error(), EnvPolicyPacks) || !strings.Contains(err.Error(), "§1.9") {
		t.Fatalf("loadInstalledPolicyPacks() = %v; want the Community refusal naming the variable and §1.9", err)
	}
}

// A deployment mode that installs the industry packs refuses on a Community
// build too, naming the mode: its migrations would retire the rows the packs
// replace, and the image carries no pack to replace them with.
func TestACommunityBuildInABankingModeRefuses(t *testing.T) {
	t.Setenv(EnvPolicyPacks, "")
	t.Setenv("DEPLOYMENT_MODE", "in-vpc-banking")
	_, err := loadInstalledPolicyPacks()
	if err == nil || !strings.Contains(err.Error(), "DEPLOYMENT_MODE") || !strings.Contains(err.Error(), "community build") || !strings.Contains(err.Error(), "§1.9") {
		t.Fatalf("loadInstalledPolicyPacks() = %v; want the Community refusal naming the mode and §1.9", err)
	}
}
