package detector

import (
	"sort"
	"strings"

	"cloudattack-community/internal/models"
)

// RunAnalysis runs all detection rules, deduplicates and sorts findings
func RunAnalysis(roles []models.Role) []models.Finding {
	collected := []models.Finding{}

	collected = append(collected, DetectPassRole(roles)...)
	collected = append(collected, DetectAssumeRole(roles)...)
	chains := DetectChains(roles)
	collected = append(collected, chains...)

	// Build set of chain keys to suppress redundant PassRole findings
	chainSet := map[string]struct{}{}
	for _, c := range chains {
		if len(c.Path) >= 2 {
			key := c.Path[0] + "->" + c.Path[1]
			chainSet[key] = struct{}{}
		}
	}

	// Deduplicate by key: Title|Role|Issue
	seen := map[string]struct{}{}
	unique := []models.Finding{}
	for _, f := range collected {
		// suppress PassRole if a chain exists for same source->target
		if f.Title == "PassRole Risk Detected" {
			// Issue is like "Can pass role <target>"
			parts := strings.SplitN(f.Issue, " ", 4)
			if len(parts) >= 4 {
				target := parts[3]
				key := f.Role + "->" + target
				if _, ok := chainSet[key]; ok {
					continue
				}
			}
		}
		pathKey := strings.Join(f.Path, "->")
		key := f.Title + "|" + f.Role + "|" + f.Issue + "|" + pathKey
		if key == "|||" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, f)
	}

	// Sort by severity: CRITICAL, HIGH, MEDIUM, LOW
	severityRank := map[string]int{
		"CRITICAL": 0,
		"HIGH":     1,
		"MEDIUM":   2,
		"LOW":      3,
	}

	sort.Slice(unique, func(i, j int) bool {
		ri := severityRank[unique[i].Severity]
		rj := severityRank[unique[j].Severity]
		if ri != rj {
			return ri < rj
		}
		if unique[i].Role != unique[j].Role {
			return unique[i].Role < unique[j].Role
		}
		return unique[i].Title < unique[j].Title
	})

	return unique
}
