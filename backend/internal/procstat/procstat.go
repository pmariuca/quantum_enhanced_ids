// Package procstat reads CPU and memory usage from /proc on Linux.
package procstat

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// CPUPercent returns the overall CPU usage percentage sampled over ~200ms.
func CPUPercent() (float64, error) {
	s1, err := readCPUStat()
	if err != nil {
		return 0, err
	}
	time.Sleep(200 * time.Millisecond)
	s2, err := readCPUStat()
	if err != nil {
		return 0, err
	}

	totalDelta := float64(s2.total - s1.total)
	idleDelta := float64(s2.idle - s1.idle)
	if totalDelta == 0 {
		return 0, nil
	}
	return (1 - idleDelta/totalDelta) * 100, nil
}

type cpuStat struct {
	total uint64
	idle  uint64
}

func readCPUStat() (cpuStat, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return cpuStat{}, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		// fields: cpu user nice system idle iowait irq softirq steal guest guest_nice
		if len(fields) < 5 {
			return cpuStat{}, fmt.Errorf("unexpected /proc/stat format")
		}
		vals := make([]uint64, len(fields)-1)
		for i, s := range fields[1:] {
			vals[i], _ = strconv.ParseUint(s, 10, 64)
		}
		var total uint64
		for _, v := range vals {
			total += v
		}
		idle := vals[3] // idle field
		if len(vals) > 4 {
			idle += vals[4] // iowait also counts as idle
		}
		return cpuStat{total: total, idle: idle}, nil
	}
	return cpuStat{}, fmt.Errorf("/proc/stat: cpu line not found")
}

// MemStats holds basic memory info in bytes.
type MemStats struct {
	Total     uint64
	Available uint64
	UsedPct   float64
}

// MemInfo reads /proc/meminfo and returns MemStats.
func MemInfo() (MemStats, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return MemStats{}, err
	}
	defer f.Close()

	kv := make(map[string]uint64)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) < 2 {
			continue
		}
		key := strings.TrimSuffix(parts[0], ":")
		val, _ := strconv.ParseUint(parts[1], 10, 64)
		kv[key] = val * 1024 // kB → bytes
	}

	total := kv["MemTotal"]
	avail := kv["MemAvailable"]
	var usedPct float64
	if total > 0 {
		usedPct = float64(total-avail) / float64(total) * 100
	}
	return MemStats{Total: total, Available: avail, UsedPct: usedPct}, nil
}
