package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type cgroupHandle struct {
	Path   string
	owned  bool
	closed bool
}

func prepareCgroup(path string) (*cgroupHandle, error) {
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		return nil, fmt.Errorf("cgroup v2 is required at /sys/fs/cgroup: %w", err)
	}
	owned := false
	if path == "" {
		path = filepath.Join("/sys/fs/cgroup", fmt.Sprintf("beap-%d", os.Getpid()))
		owned = true
	}
	if !strings.HasPrefix(filepath.Clean(path), "/sys/fs/cgroup") {
		return nil, fmt.Errorf("cgroup path must be under /sys/fs/cgroup: %s", path)
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		return nil, fmt.Errorf("create cgroup %s: %w", path, err)
	}
	return &cgroupHandle{Path: path, owned: owned}, nil
}

func (c *cgroupHandle) AddProc(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("invalid pid %d", pid)
	}
	if err := os.WriteFile(c.ProcsPath(), []byte(strconv.Itoa(pid)), 0o644); err != nil {
		return fmt.Errorf("move pid %d into %s: %w", pid, c.Path, err)
	}
	return nil
}

func (c *cgroupHandle) ProcsPath() string {
	return filepath.Join(c.Path, "cgroup.procs")
}

func (c *cgroupHandle) Close() {
	if c == nil || c.closed {
		return
	}
	c.closed = true
	if c.owned {
		_ = os.Remove(c.Path)
	}
}
