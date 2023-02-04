package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mitchellh/go-ps"
	"github.com/moolen/skouter/pkg/log"
	"github.com/thegrumpylion/namespace"
)

var logger = log.DefaultLogger

func main() {
	procs, err := ps.Processes()
	if err != nil {
		logger.Error(err, "unable to list procs")
	}

	rootns, err := namespace.FromPath("/proc/1/ns/net")
	if err != nil {
		logger.Error(err, "unable to get ns")
	}
	rootnsIno := rootns.Ino()
	rootns.Close()

	for _, proc := range procs {
		ns, err := namespace.FromPID(proc.Pid(), namespace.NET)
		if err != nil {
			continue
		}
		nsIno := ns.Ino()
		ns.Close()
		if nsIno == rootnsIno || proc.Executable() != "pause" {
			continue
		}

		cgroupPath := filepath.Join("/proc", strconv.Itoa(proc.Pid()), "cgroup")

		f, err := os.Open(cgroupPath)
		if err != nil {
			logger.Error(err, "unable to open cgroup path", "path", cgroupPath)
		}
		defer f.Close()
		cgrp, err := parseCgroupFromReader(f)
		if err != nil {
			logger.Error(err, "unable to parse cgroup")
		}

		logger.Info("found proc", "pid", proc.Pid(), "ppid", proc.PPid(), "executable", proc.Executable(), "ns", nsIno, "cgroup", cgrp)
	}
}

// helper function for ParseCgroupFile to make testing easier
func parseCgroupFromReader(r io.Reader) (map[string]string, error) {
	s := bufio.NewScanner(r)
	cgroups := make(map[string]string)

	for s.Scan() {
		text := s.Text()
		// from cgroups(7):
		// /proc/[pid]/cgroup
		// ...
		// For each cgroup hierarchy ... there is one entry
		// containing three colon-separated fields of the form:
		//     hierarchy-ID:subsystem-list:cgroup-path
		parts := strings.SplitN(text, ":", 3)
		if len(parts) < 3 {
			return nil, fmt.Errorf("invalid cgroup entry: must contain at least two colons: %v", text)
		}

		for _, subs := range strings.Split(parts[1], ",") {
			cgroups[subs] = parts[2]
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}

	return cgroups, nil
}
