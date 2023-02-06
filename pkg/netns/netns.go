package netns

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/mitchellh/go-ps"
	"github.com/moolen/skouter/pkg/log"
	"github.com/thegrumpylion/namespace"
)

var logger = log.DefaultLogger

type NetNS struct {
	CGroup  string
	NetNSID uint64
	PodUUID string
}

func RootNS() (uint64, error) {
	rootns, err := namespace.FromPath("/proc/1/ns/net")
	if err != nil {
		return 0, err
	}
	rootnsIno := rootns.Ino()
	rootns.Close()
	return rootnsIno, nil
}

func List() ([]NetNS, error) {
	out := []NetNS{}
	procs, err := ps.Processes()
	if err != nil {
		return nil, err
	}

	rootnsIno, err := RootNS()
	if err != nil {
		return nil, err
	}
	for _, proc := range procs {
		ns, err := namespace.FromPID(proc.Pid(), namespace.NET)
		if err != nil {
			continue
		}
		nsIno := ns.Ino()
		ns.Close()
		if nsIno == rootnsIno {
			continue
		}

		cgroupPath := filepath.Join("/proc", strconv.Itoa(proc.Pid()), "cgroup")
		f, err := os.Open(cgroupPath)
		if err != nil {
			logger.Error(err, "unable to open cgroup path", "path", cgroupPath)
			continue
		}
		defer f.Close()
		cgrp, err := parseCgroupFromReader(f)
		if err != nil {
			logger.Error(err, "unable to parse cgroup")
			continue
		}
		if cgrp == "" {
			continue
		}

		matches := podUUIDRE.FindStringSubmatch(cgrp)
		if len(matches) != 2 {
			continue
		}
		podUUID := strings.Replace(matches[1], "_", "-", -1)

		out = append(out, NetNS{
			CGroup:  cgrp,
			NetNSID: nsIno,
			PodUUID: podUUID,
		})
	}
	return out, nil
}

var podUUIDRE = regexp.MustCompile("kubepods.slice.*-pod(.+).slice")

// helper function for ParseCgroupFile to make testing easier
func parseCgroupFromReader(r io.Reader) (string, error) {
	s := bufio.NewScanner(r)
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
			return "", fmt.Errorf("invalid cgroup entry: must contain at least two colons: %v", text)
		}

		if strings.Contains(parts[2], "kubepods.slice") {
			return parts[2], nil
		}
	}
	if err := s.Err(); err != nil {
		return "", err
	}

	return "", nil
}
