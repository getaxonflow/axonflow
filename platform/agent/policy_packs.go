// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/policypack"
	"axonflow/platform/shared/deploymode"
	"axonflow/platform/shared/edition"
	sharedpolicy "axonflow/platform/shared/policy"
	"axonflow/platform/shared/retiredenv"
)

// INSTALLED POLICY PACKS (PRD v11 §1.9, #4126)
//
// A deployment installs an add-on policy pack by naming it in
// AXONFLOW_POLICY_PACKS. Installing replaces the pack's retired seed script: the
// pack is never written to static_policies. At boot this process loads each
// named pack from the directory the Enterprise image carries them in, compiles
// its detectors into the shared engine's detector layer, and hands the pack to
// the anchored enforcer, which composes its document on every organization root
// beside the baseline pack. The deployment mode's own packs (the industry
// verticals, #4141) join this set: see industryPolicyPacks.

// EnvPolicyPacks names the add-on policy packs this deployment installs,
// comma-separated. Empty installs none.
const EnvPolicyPacks = "AXONFLOW_POLICY_PACKS"

// industryPolicyPacks are the policy packs a deployment mode installs, by the
// industry migration category it applies (#4141, PRD v11 §1.9). A mode that
// applies industry/banking - in-vpc-banking and saas - installs the three
// banking packs whatever AXONFLOW_POLICY_PACKS names. Migration
// industry/banking/402 retires the rows those packs replace, at the same boot,
// so no banking deployment is without the controls between the two.
var industryPolicyPacks = map[string][]string{
	"industry/banking": {"mas-feat", "rbi", "sebi"},
}

// modePolicyPacks are the packs this process's deployment mode installs, and
// the mode, resolved exactly as the migration selector resolves it.
func modePolicyPacks() (string, []string, error) {
	mode, err := resolveDeploymentMode(deploymode.Current())
	if err != nil {
		return "", nil, err
	}
	var out []string
	for _, category := range canonicalDeploymentModes[mode] {
		out = append(out, industryPolicyPacks[category]...)
	}
	return mode, out, nil
}

// policyPackDir is where the Enterprise image carries the policy packs
// (platform/agent/Dockerfile copies ee/policy-packs there). A variable so a test
// can point the loader at the repository's copy.
var policyPackDir = "/opt/axonflow/policy-packs"

// installedPolicyPacks are the packs this process installed at boot, and
// installedPackDetectors their detectors compiled for the shared engine. Both
// are set once by installPolicyPacks, before the engine and the enforcer that
// read them are built.
var (
	installedPolicyPacks   []*policypack.Pack
	installedPackDetectors []sharedpolicy.CompiledPolicy
)

// installPolicyPacks loads the installed packs and compiles their detectors, or
// says why this process must not start.
func installPolicyPacks() error {
	packs, err := loadInstalledPolicyPacks()
	if err != nil {
		return err
	}
	detectors, err := sharedpolicy.CompileInstalledDetectors(packs)
	if err != nil {
		return fmt.Errorf("%s: %w", EnvPolicyPacks, err)
	}
	installedPolicyPacks, installedPackDetectors = packs, detectors
	for _, p := range packs {
		log.Printf("✅ [POLICY-PACK] installed %s v%d: %d detector(s) (PRD v11 §1.9)", p.Source.ID, p.Source.Version, len(p.Source.Detectors))
	}
	return nil
}

// instantiatePolicyPacks instantiates the installed packs for the realms this
// deployment's identity plane mints principals in, resolving the deployment
// vocabulary for that alone: which realms a person can answer in is settled by
// the identity bootstrap, which has run when the enforcer is installed.
func instantiatePolicyPacks(packs []*policypack.Pack) ([]activation.InstalledPack, error) {
	if len(packs) == 0 {
		return nil, nil
	}
	snap, err := resolveDeploymentVocabulary()
	if err != nil {
		return nil, fmt.Errorf("%s: instantiating the installed policy packs needs the deployment vocabulary: %w", EnvPolicyPacks, err)
	}
	installed, err := activation.InstallPacks(snap, packs)
	if err != nil {
		return nil, fmt.Errorf("%s (%s §1.9): %w", EnvPolicyPacks, retiredenv.PRD, err)
	}
	return installed, nil
}

// loadInstalledPolicyPacks reads EnvPolicyPacks and loads each named pack, or
// says why this process must not start.
//
// The deployment mode's own packs (industryPolicyPacks) join the names the
// variable gives, and a pack both name is installed once.
//
// It refuses, naming the variable (or the mode) and PRD §1.9:
//   - any value on a Community build, and a mode that installs packs on one,
//     because the packs are Enterprise add-ons and a Community image carries none;
//   - a name the image carries no pack for, and a name given twice;
//   - a pack whose committed document is not what its source compiles to
//     (policypack.Load), so a hand-edited document cannot be installed.
func loadInstalledPolicyPacks() ([]*policypack.Pack, error) {
	raw := strings.TrimSpace(os.Getenv(EnvPolicyPacks))
	mode, byMode, err := modePolicyPacks()
	if err != nil {
		return nil, err
	}
	if raw == "" && len(byMode) == 0 {
		return nil, nil
	}
	refuse := func(why string) error {
		return fmt.Errorf("%s=%q %s (%s §1.9): unset it, or name only packs this image carries", EnvPolicyPacks, raw, why, retiredenv.PRD)
	}
	if edition.Current != edition.Enterprise {
		if raw == "" {
			return nil, fmt.Errorf("DEPLOYMENT_MODE=%q installs the industry policy packs %v, and a %s build carries none (%s §1.9): run an Enterprise image in this mode",
				mode, byMode, edition.Current, retiredenv.PRD)
		}
		return nil, refuse(fmt.Sprintf("installs an Enterprise add-on policy pack on a %s build, which carries none", edition.Current))
	}
	seen := map[string]bool{}
	var names []string
	for _, n := range strings.Split(raw, ",") {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if seen[n] {
			return nil, refuse(fmt.Sprintf("names the pack %q twice", n))
		}
		seen[n] = true
		names = append(names, n)
	}
	// The mode's packs join what the operator named; a pack both name is one install.
	for _, n := range byMode {
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	sort.Strings(names)
	packs := make([]*policypack.Pack, 0, len(names))
	for _, n := range names {
		// A name is one path segment, and it is the pack's own id: a name that
		// could climb out of the pack directory is not a pack name.
		if n != filepath.Base(n) || strings.ContainsAny(n, `/\`) {
			return nil, refuse(fmt.Sprintf("names %q, which is not a pack name", n))
		}
		dir := filepath.Join(policyPackDir, n)
		source, err := os.ReadFile(filepath.Join(dir, "pack.json"))
		if err != nil {
			return nil, refuse(fmt.Sprintf("names %q, and this image carries no such pack (%v)", n, err))
		}
		committed, err := os.ReadFile(filepath.Join(dir, "document.json"))
		if err != nil {
			return nil, refuse(fmt.Sprintf("names %q, whose compiled document this image does not carry (%v)", n, err))
		}
		p, err := policypack.Load(source, committed)
		if err != nil {
			return nil, refuse(fmt.Sprintf("names %q, which does not load: %v", n, err))
		}
		if p.Source.ID != n {
			return nil, refuse(fmt.Sprintf("names %q, and the pack in that directory is %q", n, p.Source.ID))
		}
		packs = append(packs, p)
	}
	return packs, nil
}
