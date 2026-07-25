// Package uci provides the UCIRunner interface and implementations for
// running UCI commands on OpenWrt devices.
package uci

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// UCIRunner abstracts the uci CLI so that business logic can be tested
// without a real OpenWrt device.
type UCIRunner interface {
	Get(pkg, section, option string) (string, error)
	Set(pkg, section, option, value string) error
	SetType(pkg, section, sectionType string) error
	Add(pkg, sectionType string) (string, error)
	AddList(pkg, section, option, value string) error
	Delete(pkg, section string) error
	DeleteOption(pkg, section, option string) error
	Commit(pkg string) error
	Revert(pkg string) error
	Export(pkg string) (string, error)
	Show(pkg string) (string, error)
	// ExecRaw runs the uci CLI with arbitrary args (for ad-hoc commands from server).
	ExecRaw(args ...string) (string, error)
	// ExecCmd runs an arbitrary executable directly (not via uci), e.g. an init script.
	ExecCmd(path string, args ...string) (string, error)
}

// RealUCIRunner calls the uci CLI via os/exec.
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

func (r *RealUCIRunner) Get(pkg, section, option string) (string, error) {
	return run("get", fmt.Sprintf("%s.%s.%s", pkg, section, option))
}

func (r *RealUCIRunner) Set(pkg, section, option, value string) error {
	_, err := run("set", fmt.Sprintf("%s.%s.%s=%s", pkg, section, option, value))
	return err
}

func (r *RealUCIRunner) SetType(pkg, section, sectionType string) error {
	_, err := run("set", fmt.Sprintf("%s.%s=%s", pkg, section, sectionType))
	return err
}

func (r *RealUCIRunner) Add(pkg, sectionType string) (string, error) {
	return run("add", pkg, sectionType)
}

func (r *RealUCIRunner) AddList(pkg, section, option, value string) error {
	_, err := run("add_list", fmt.Sprintf("%s.%s.%s=%s", pkg, section, option, value))
	return err
}

func (r *RealUCIRunner) Delete(pkg, section string) error {
	_, err := run("delete", fmt.Sprintf("%s.%s", pkg, section))
	return err
}

func (r *RealUCIRunner) DeleteOption(pkg, section, option string) error {
	_, err := run("delete", fmt.Sprintf("%s.%s.%s", pkg, section, option))
	return err
}

func (r *RealUCIRunner) Commit(pkg string) error {
	_, err := run("commit", pkg)
	return err
}

func (r *RealUCIRunner) Revert(pkg string) error {
	_, err := run("revert", pkg)
	return err
}

func (r *RealUCIRunner) Export(pkg string) (string, error) {
	return run("export", pkg)
}

func (r *RealUCIRunner) Show(pkg string) (string, error) {
	return run("show", pkg)
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

// MockUCIRunner records all calls for test assertions.
// Inject errors via the Errors map keyed by the command string.
// Inject output via the Results map keyed by the command string.
type MockUCIRunner struct {
	Calls   []string
	Errors  map[string]error
	Results map[string]string
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

func (m *MockUCIRunner) Get(pkg, section, option string) (string, error) {
	cmd := fmt.Sprintf("get %s.%s.%s", pkg, section, option)
	m.record(cmd)
	return "", m.err(cmd)
}

func (m *MockUCIRunner) Set(pkg, section, option, value string) error {
	cmd := fmt.Sprintf("set %s.%s.%s=%s", pkg, section, option, value)
	m.record(cmd)
	return m.err(cmd)
}

func (m *MockUCIRunner) SetType(pkg, section, sectionType string) error {
	cmd := fmt.Sprintf("set-type %s.%s=%s", pkg, section, sectionType)
	m.record(cmd)
	return m.err(cmd)
}

func (m *MockUCIRunner) Add(pkg, sectionType string) (string, error) {
	cmd := fmt.Sprintf("add %s %s", pkg, sectionType)
	m.record(cmd)
	return fmt.Sprintf("cfg%06x", len(m.Calls)), m.err(cmd)
}

func (m *MockUCIRunner) AddList(pkg, section, option, value string) error {
	cmd := fmt.Sprintf("add_list %s.%s.%s=%s", pkg, section, option, value)
	m.record(cmd)
	return m.err(cmd)
}

func (m *MockUCIRunner) Delete(pkg, section string) error {
	cmd := fmt.Sprintf("delete %s.%s", pkg, section)
	m.record(cmd)
	return m.err(cmd)
}

func (m *MockUCIRunner) DeleteOption(pkg, section, option string) error {
	cmd := fmt.Sprintf("delete-option %s.%s.%s", pkg, section, option)
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

func (m *MockUCIRunner) Export(pkg string) (string, error) {
	cmd := fmt.Sprintf("export %s", pkg)
	m.record(cmd)
	if m.Results != nil {
		if out, ok := m.Results[cmd]; ok {
			return out, m.err(cmd)
		}
	}
	return "", m.err(cmd)
}

func (m *MockUCIRunner) Show(pkg string) (string, error) {
	cmd := fmt.Sprintf("show %s", pkg)
	m.record(cmd)
	if m.Results != nil {
		if out, ok := m.Results[cmd]; ok {
			return out, m.err(cmd)
		}
	}
	return "", m.err(cmd)
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
