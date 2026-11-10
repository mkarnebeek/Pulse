package hostagent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

const inspectionTestAPTOutput = "Inst zlib1g [1:1.3.1-1+b1] (1:1.3.1-1+deb13u1 Debian-Security:13/stable-security [amd64])\n" +
	"Inst vim-tiny [2:9.1.1230-2+deb13u1] (2:9.1.1230-2+deb13u2 Debian-Security:13/stable-security [amd64])\n"

// Regression: a collector without an action runner (the default root
// profile) reported "package update inspection failed" with a pending count
// of 0, because its simulation went through typed-action containment, which
// needs PULSE_AGENT_RUNNER_STATE_DIR and pulse-agent-runner.service.
func TestCollectorPackageUpdateSnapshotDoesNotRequireActionRunner(t *testing.T) {
	updates, _ := configurePackageManagers("debian", nil, nil)
	if updates.inspect == nil ||
		reflect.ValueOf(updates.inspect).Pointer() != reflect.ValueOf(runPackageInspectionCommand).Pointer() {
		t.Fatal("collector package manager must run the read-only simulation through runPackageInspectionCommand")
	}

	updates.lookPath = func(string) (string, error) { return "/usr/bin/apt-get", nil }
	updates.stat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	updates.run = func(context.Context, []string, string, ...string) packageUpdateCommandResult {
		t.Fatal("collector simulation must not go through typed-action containment")
		return packageUpdateCommandResult{}
	}
	var gotName string
	var gotArgs []string
	updates.inspect = func(_ context.Context, env []string, name string, args ...string) packageUpdateCommandResult {
		if len(env) != 0 {
			t.Fatalf("inspection env = %v, want none", env)
		}
		gotName, gotArgs = name, args
		return packageUpdateCommandResult{stdout: inspectionTestAPTOutput}
	}

	snapshot := updates.Snapshot(context.Background(), true)
	if !snapshot.Supported || snapshot.Manager != "apt" || snapshot.Error != "" {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	if snapshot.PendingCount != 2 || len(snapshot.Packages) != 2 || snapshot.InventoryHash == "" {
		t.Fatalf("snapshot did not report the simulated upgrades: %#v", snapshot)
	}
	if gotName != "apt-get" || !reflect.DeepEqual(gotArgs, aptSimulateUpgradeArgs) {
		t.Fatalf("inspection = %s %v, want apt-get %v", gotName, gotArgs, aptSimulateUpgradeArgs)
	}
}

func TestActionRunnerPackageUpdateSnapshotStaysContained(t *testing.T) {
	m := newPackageUpdateManager("debian", newPackageManagerLease())
	if m.inspect != nil {
		t.Fatal("the action runner's package manager must keep its simulations contained")
	}
	m.lookPath = func(string) (string, error) { return "/usr/bin/apt-get", nil }
	m.stat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	contained := false
	m.run = func(_ context.Context, _ []string, name string, args ...string) packageUpdateCommandResult {
		if name == "apt-get" && reflect.DeepEqual(args, aptSimulateUpgradeArgs) {
			contained = true
		}
		return packageUpdateCommandResult{stdout: inspectionTestAPTOutput}
	}
	if snapshot := m.Snapshot(context.Background(), true); snapshot.PendingCount != 2 || !contained {
		t.Fatalf("contained simulation not used: contained=%v snapshot=%#v", contained, snapshot)
	}
}

func TestRunPackageInspectionCommandAcceptsOnlyTheSimulation(t *testing.T) {
	original := packageUpdateLookPath
	t.Cleanup(func() { packageUpdateLookPath = original })
	packageUpdateLookPath = func(string) (string, error) {
		t.Fatal("a refused invocation must not resolve or execute anything")
		return "", nil
	}

	for _, tc := range []struct {
		name string
		env  []string
		cmd  string
		args []string
	}{
		{name: "metadata refresh", cmd: "apt-get", args: []string{"update"}},
		{name: "install", cmd: "apt-get", args: []string{"-y", "--no-remove", "-o", "Dpkg::Options::=--force-confold", "upgrade"}},
		{name: "clean", cmd: "apt-get", args: []string{"clean"}},
		{name: "other tool", cmd: "dpkg", args: []string{"--audit"}},
		{name: "extra argument", cmd: "apt-get", args: append(append([]string{}, aptSimulateUpgradeArgs...), "--fix-broken")},
		{name: "environment", env: []string{"DEBIAN_FRONTEND=noninteractive"}, cmd: "apt-get", args: aptSimulateUpgradeArgs},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := runPackageInspectionCommand(context.Background(), tc.env, tc.cmd, tc.args...)
			if !errors.Is(result.err, errPackageInspectionInvocation) || result.exitCode != -1 {
				t.Fatalf("result = %#v, want refusal", result)
			}
		})
	}
}

// useFakeAPTGet points packageUpdateLookPath at a shell script stand-in for
// apt-get with the given body.
func useFakeAPTGet(t *testing.T, body string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell script stand-in for apt-get")
	}
	fake := filepath.Join(t.TempDir(), "apt-get")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	original := packageUpdateLookPath
	t.Cleanup(func() { packageUpdateLookPath = original })
	packageUpdateLookPath = func(string) (string, error) { return fake, nil }
}

func TestRunPackageInspectionCommandReportsExitCode(t *testing.T) {
	useFakeAPTGet(t, "echo 'E: Could not open lock file' >&2\nexit 100\n")
	result := runPackageInspectionCommand(context.Background(), nil, "apt-get", aptSimulateUpgradeArgs...)
	if result.err == nil || result.exitCode != 100 || !strings.Contains(result.stderr, "lock file") {
		t.Fatalf("result = %#v", result)
	}
}

func TestRunPackageInspectionCommandRunsSimulationDirectly(t *testing.T) {
	useFakeAPTGet(t, "echo \"args=$*\" >&2\n"+
		"echo \"lc_all=$LC_ALL\" >&2\n"+
		"printf '%s' \"$PULSE_TEST_OUTPUT\"\n"+
		"printf '"+strings.ReplaceAll(inspectionTestAPTOutput, "\n", "\\n")+"'\n")
	t.Setenv("PULSE_TEST_OUTPUT", "leaked\n")

	result := runPackageInspectionCommand(context.Background(), nil, "apt-get", aptSimulateUpgradeArgs...)
	if result.err != nil || result.exitCode != 0 {
		t.Fatalf("result = %#v", result)
	}
	if countAPTSimulatedUpgrades(result.stdout) != 2 {
		t.Fatalf("stdout = %q", result.stdout)
	}
	if strings.Contains(result.stdout, "leaked") {
		t.Fatalf("inspection inherited the agent environment: %q", result.stdout)
	}
	if !strings.Contains(result.stderr, "args=-s -o Debug::NoLocking=1 upgrade") || !strings.Contains(result.stderr, "lc_all=C") {
		t.Fatalf("stderr = %q", result.stderr)
	}
}
