// Package uci provides the UCIRunner interface and implementations for
// running UCI commands on OpenWrt devices.
package uci

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// UCIRunner abstracts UCI access so that business logic can be tested without
// a real OpenWrt device. Reads and most writes go through rpcd's `uci` ubus
// object (JSON in, JSON out — see RealUCIRunner) rather than shelling out to
// the `uci` CLI and parsing its text output; RetypeExisting is the one
// exception, kept on the CLI (see its doc comment).
type UCIRunner interface {
	// GetSections fetches every section currently in pkg from the device, in
	// on-device declaration order. Returns a non-nil error if the package
	// doesn't exist yet or the ubus call otherwise fails — callers with a
	// "doesn't exist yet means empty" contract have historically treated any
	// error here as "no sections."
	GetSections(pkg string) ([]Section, error)
	// Add creates a new section of sectionType in pkg. If name is non-empty
	// the section is created with that name (idempotent-creation upsert
	// semantics belong to the caller, which should only call Add when it has
	// already established via GetSections that the name doesn't exist yet);
	// if name is empty an anonymous section is created and its generated id
	// is returned.
	Add(pkg, sectionType, name string) (id string, err error)
	// SetValues batch-sets every option in values on an existing section in
	// one call. A []string value sets a UCI list option, replacing its
	// entire prior contents; any other value is set as a scalar.
	SetValues(pkg, sectionID string, values map[string]interface{}) error
	// DeleteOptions removes the named options from an existing section,
	// leaving the section and its other options intact.
	DeleteOptions(pkg, sectionID string, options []string) error
	// Delete removes an entire section.
	Delete(pkg, sectionID string) error
	Commit(pkg string) error
	Revert(pkg string) error
	// RetypeExisting changes an already-existing section's type in place
	// (`uci set pkg.section=type`). rpcd's uci `set` method has no parameter
	// to change an existing section's type (only `add` sets type, and only
	// at creation) — this is the one write operation this package could not
	// confirm a ubus equivalent for, so it stays on the CLI. It's only ever
	// needed for the rare case of a named section that already exists under
	// the wrong type; the common create/update paths never call it.
	RetypeExisting(pkg, sectionID, sectionType string) error
	// ExecRaw runs the uci CLI with arbitrary args (for ad-hoc commands from server).
	ExecRaw(args ...string) (string, error)
	// ExecCmd runs an arbitrary executable directly (not via uci), e.g. an init script.
	ExecCmd(path string, args ...string) (string, error)
	// ExecShell runs command through /bin/sh -c, capturing combined stdout+stderr, bounded by
	// timeout. Unlike ExecCmd/ExecRaw, this genuinely invokes a shell — pipes, redirects, and
	// multi-statement scripts all work as a real script would. The returned exitCode reflects the
	// process's actual exit status even when non-zero (that's a legitimate result, not a failure);
	// err is only set for exec-level failures (command not found, timeout, kill).
	ExecShell(command string, timeout time.Duration) (output string, exitCode int, err error)
}

// RealUCIRunner calls the uci CLI (RetypeExisting/ExecRaw/ExecCmd/ExecShell) and
// rpcd's uci ubus object (everything else, via `ubus call uci <method> <json>`).
type RealUCIRunner struct{}

// uciTimeout is the maximum time a single uci CLI call is allowed to run.
// A hung uci process would otherwise block the Paho MQTT message-dispatch
// goroutine permanently, freezing the entire agent.
const uciTimeout = 30 * time.Second

func run(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), uciTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "uci", args...).Output()
	if err != nil {
		return "", fmt.Errorf("uci %s: %w", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out)), nil
}

// ubusUCI calls `ubus call uci <method> <json-encoded params>` and returns its raw stdout.
func (r *RealUCIRunner) ubusUCI(method string, params interface{}) (string, error) {
	body, err := json.Marshal(params)
	if err != nil {
		return "", fmt.Errorf("marshal uci %s params: %w", method, err)
	}
	return r.ExecCmd("ubus", "call", "uci", method, string(body))
}

func (r *RealUCIRunner) GetSections(pkg string) ([]Section, error) {
	out, err := r.ubusUCI("get", map[string]string{"config": pkg})
	if err != nil {
		return nil, err
	}
	return decodeUbusUCIGet(out)
}

func (r *RealUCIRunner) Add(pkg, sectionType, name string) (string, error) {
	params := map[string]interface{}{"config": pkg, "type": sectionType}
	if name != "" {
		params["name"] = name
	}
	out, err := r.ubusUCI("add", params)
	if err != nil {
		return "", err
	}
	var resp struct {
		Section string `json:"section"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return "", fmt.Errorf("decode uci add response: %w", err)
	}
	if resp.Section == "" {
		return "", fmt.Errorf("uci add %s %s: no section id in response", pkg, sectionType)
	}
	return resp.Section, nil
}

func (r *RealUCIRunner) SetValues(pkg, sectionID string, values map[string]interface{}) error {
	if len(values) == 0 {
		return nil
	}
	_, err := r.ubusUCI("set", map[string]interface{}{"config": pkg, "section": sectionID, "values": values})
	return err
}

func (r *RealUCIRunner) DeleteOptions(pkg, sectionID string, options []string) error {
	if len(options) == 0 {
		return nil
	}
	_, err := r.ubusUCI("delete", map[string]interface{}{"config": pkg, "section": sectionID, "options": options})
	return err
}

func (r *RealUCIRunner) Delete(pkg, sectionID string) error {
	_, err := r.ubusUCI("delete", map[string]interface{}{"config": pkg, "section": sectionID})
	return err
}

func (r *RealUCIRunner) Commit(pkg string) error {
	_, err := r.ubusUCI("commit", map[string]string{"config": pkg})
	return err
}

func (r *RealUCIRunner) Revert(pkg string) error {
	_, err := r.ubusUCI("revert", map[string]string{"config": pkg})
	return err
}

func (r *RealUCIRunner) RetypeExisting(pkg, sectionID, sectionType string) error {
	_, err := run("set", fmt.Sprintf("%s.%s=%s", pkg, sectionID, sectionType))
	return err
}

func (r *RealUCIRunner) ExecRaw(args ...string) (string, error) {
	return run(args...)
}

func (r *RealUCIRunner) ExecCmd(path string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), uciTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, args...).Output()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w", path, strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out)), nil
}

func (r *RealUCIRunner) ExecShell(command string, timeout time.Duration) (string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/bin/sh", "-c", command).CombinedOutput()
	output := strings.TrimSpace(string(out))
	// Check the deadline first: a killed-by-timeout process still satisfies errors.As(err,
	// &exitErr) below (a signal-terminated process is a legitimate *exec.ExitError with
	// ExitCode() == -1), which would otherwise be indistinguishable from a script that
	// genuinely, deliberately exits -1 on its own.
	if ctx.Err() == context.DeadlineExceeded {
		return output, -1, fmt.Errorf("sh -c: timed out after %s", timeout)
	}
	if err == nil {
		return output, 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return output, exitErr.ExitCode(), nil
	}
	return output, -1, fmt.Errorf("sh -c: %w", err)
}

// MockUCIRunner records all calls for test assertions.
// Inject errors via the Errors map keyed by the command string.
// Inject output via the Results map keyed by the command string.
// Inject GetSections' return value via Sections, keyed by package name.
// Inject a non-zero ExecShell exit code via the ExitCodes map keyed by "shell <command>".
// SetValues/Add calls carrying a map or requiring exact value assertions are also recorded,
// in order, into SetValuesCalls/AddCalls — a stringified map has nondeterministic key order,
// so those two are asserted on directly rather than via the Calls string log.
type MockUCIRunner struct {
	Calls          []string
	Errors         map[string]error
	Results        map[string]string
	ExitCodes      map[string]int
	Sections       map[string][]Section
	SetValuesCalls []SetValuesCall
	AddCalls       []AddCall

	addSeq int
}

// SetValuesCall records one MockUCIRunner.SetValues invocation.
type SetValuesCall struct {
	Pkg     string
	Section string
	Values  map[string]interface{}
}

// AddCall records one MockUCIRunner.Add invocation.
type AddCall struct {
	Pkg, SectionType, Name string
}

func (m *MockUCIRunner) err(cmd string) error {
	if m.Errors != nil {
		return m.Errors[cmd]
	}
	return nil
}

func (m *MockUCIRunner) record(cmd string) {
	m.Calls = append(m.Calls, cmd)
}

func (m *MockUCIRunner) GetSections(pkg string) ([]Section, error) {
	cmd := fmt.Sprintf("sections %s", pkg)
	m.record(cmd)
	if err := m.err(cmd); err != nil {
		return nil, err
	}
	if m.Sections != nil {
		return m.Sections[pkg], nil
	}
	return nil, nil
}

func (m *MockUCIRunner) Add(pkg, sectionType, name string) (string, error) {
	var cmd string
	if name != "" {
		cmd = fmt.Sprintf("add %s %s %s", pkg, sectionType, name)
	} else {
		cmd = fmt.Sprintf("add %s %s", pkg, sectionType)
	}
	m.record(cmd)
	m.AddCalls = append(m.AddCalls, AddCall{Pkg: pkg, SectionType: sectionType, Name: name})
	if err := m.err(cmd); err != nil {
		return "", err
	}
	if name != "" {
		return name, nil
	}
	m.addSeq++
	return fmt.Sprintf("cfg%06x", m.addSeq), nil
}

func (m *MockUCIRunner) SetValues(pkg, sectionID string, values map[string]interface{}) error {
	cmd := fmt.Sprintf("setvalues %s.%s", pkg, sectionID)
	m.record(cmd)
	m.SetValuesCalls = append(m.SetValuesCalls, SetValuesCall{Pkg: pkg, Section: sectionID, Values: values})
	return m.err(cmd)
}

func (m *MockUCIRunner) DeleteOptions(pkg, sectionID string, options []string) error {
	cmd := fmt.Sprintf("deleteoptions %s.%s %v", pkg, sectionID, options)
	m.record(cmd)
	return m.err(cmd)
}

func (m *MockUCIRunner) Delete(pkg, sectionID string) error {
	cmd := fmt.Sprintf("delete %s.%s", pkg, sectionID)
	m.record(cmd)
	return m.err(cmd)
}

func (m *MockUCIRunner) Commit(pkg string) error {
	cmd := fmt.Sprintf("commit %s", pkg)
	m.record(cmd)
	return m.err(cmd)
}

func (m *MockUCIRunner) Revert(pkg string) error {
	cmd := fmt.Sprintf("revert %s", pkg)
	m.record(cmd)
	return m.err(cmd)
}

func (m *MockUCIRunner) RetypeExisting(pkg, sectionID, sectionType string) error {
	cmd := fmt.Sprintf("set-type %s.%s=%s", pkg, sectionID, sectionType)
	m.record(cmd)
	return m.err(cmd)
}

func (m *MockUCIRunner) ExecRaw(args ...string) (string, error) {
	cmd := "raw " + strings.Join(args, " ")
	m.record(cmd)
	return "", m.err(cmd)
}

func (m *MockUCIRunner) ExecCmd(path string, args ...string) (string, error) {
	cmd := "cmd " + path
	if len(args) > 0 {
		cmd += " " + strings.Join(args, " ")
	}
	m.record(cmd)
	if m.Results != nil {
		if out, ok := m.Results[cmd]; ok {
			return out, m.err(cmd)
		}
	}
	return "", m.err(cmd)
}

func (m *MockUCIRunner) ExecShell(command string, _ time.Duration) (string, int, error) {
	cmd := "shell " + command
	m.record(cmd)
	exitCode := 0
	if m.ExitCodes != nil {
		exitCode = m.ExitCodes[cmd]
	}
	out := ""
	if m.Results != nil {
		out = m.Results[cmd]
	}
	return out, exitCode, m.err(cmd)
}
