package detector

import (
	"fmt"
	"sort"
	"strings"

	"cloudattack-community/internal/models"
)

// RunTerraformAnalysis applies the same IAM rules to both plan states, then
// classifies matched risk patterns. Unmatched findings are never treated as
// introduced/resolved unless every resource needed to establish absence is
// explicitly represented in that side of resource_changes.
func RunTerraformAnalysis(plan models.TerraformPlan) []models.Finding {
	before := RunAnalysis(plan.BeforeRoles)
	after := RunAnalysis(plan.AfterRoles)
	usedBefore := make([]bool, len(before))
	usedAfter := make([]bool, len(after))
	results := make([]models.Finding, 0, len(before)+len(after)+len(plan.Uncertainties))

	beforeExact := indexFindings(before, func(f models.Finding) string { return f.MatchKey })
	afterExact := indexFindings(after, func(f models.Finding) string { return f.MatchKey })
	for key, bi := range beforeExact {
		ai, ok := afterExact[key]
		if !ok {
			continue
		}
		usedBefore[bi], usedAfter[ai] = true, true
		results = append(results, classifyPair(before[bi], after[ai], plan))
	}

	// If the same statement remains but its target/context changes, pair it as
	// Changed only when the statement identity is unique on both sides.
	beforeGroups := map[string][]int{}
	afterGroups := map[string][]int{}
	resourceKey := func(f models.Finding) string {
		if f.RuleID == "" || f.RoleAddress == "" || f.ResourceAddress == "" || f.StatementIndex == nil {
			return ""
		}
		return fmt.Sprintf("%s|%s|%s", f.RuleID, canonicalAddress(f.RoleAddress, "after", plan), canonicalAddress(f.ResourceAddress, "after", plan))
	}
	statementKey := func(f models.Finding) string {
		if k := resourceKey(f); k != "" {
			return fmt.Sprintf("%s|%d", k, *f.StatementIndex)
		}
		return ""
	}
	fingerprintKey := func(f models.Finding) string {
		if k := resourceKey(f); k != "" {
			return k + "|" + f.ContextFingerprint
		}
		return ""
	}

	// Statement ordering can change when an unrelated statement is inserted.
	// Identical context within the same Terraform resource remains a safe match.
	beforeFingerprints := groupFindingIndexes(before, usedBefore, fingerprintKey)
	afterFingerprints := groupFindingIndexes(after, usedAfter, fingerprintKey)
	for key, bis := range beforeFingerprints {
		if len(bis) != 1 || len(afterFingerprints[key]) != 1 {
			continue
		}
		beforeIndex, afterIndex := bis[0], afterFingerprints[key][0]
		usedBefore[beforeIndex], usedAfter[afterIndex] = true, true
		results = append(results, classifyPair(before[beforeIndex], after[afterIndex], plan))
	}
	for i, f := range before {
		if !usedBefore[i] {
			if k := statementKey(f); k != "" {
				beforeGroups[k] = append(beforeGroups[k], i)
			}
		}
	}
	for i, f := range after {
		if !usedAfter[i] {
			if k := statementKey(f); k != "" {
				afterGroups[k] = append(afterGroups[k], i)
			}
		}
	}
	for key, bis := range beforeGroups {
		ais := afterGroups[key]
		if len(bis) != 1 || len(ais) != 1 {
			continue
		}
		bi, ai := bis[0], ais[0]
		usedBefore[bi], usedAfter[ai] = true, true
		f := classifyPair(before[bi], after[ai], plan)
		if f.ChangeClassification != models.ChangeUnknown && f.ContextFingerprint != before[bi].ContextFingerprint {
			f.ChangeClassification = models.ChangeChanged
			f.ChangeSummary = "The supported risk pattern persists with materially changed IAM context."
		}
		results = append(results, f)
	}

	// Remaining findings in a resource may have shifted statement indexes.
	// Pair only a unique one-to-one remainder; ambiguous multi-finding groups
	// stay Unknown instead of manufacturing introduced/resolved events.
	resourceBefore := groupFindingIndexes(before, usedBefore, resourceKey)
	resourceAfter := groupFindingIndexes(after, usedAfter, resourceKey)
	ambiguousBefore, ambiguousAfter := map[int]bool{}, map[int]bool{}
	for key, bis := range resourceBefore {
		ais := resourceAfter[key]
		if len(bis) == 1 && len(ais) == 1 {
			bi, ai := bis[0], ais[0]
			usedBefore[bi], usedAfter[ai] = true, true
			f := classifyPair(before[bi], after[ai], plan)
			if f.ChangeClassification != models.ChangeUnknown && f.ContextFingerprint != before[bi].ContextFingerprint {
				f.ChangeClassification = models.ChangeChanged
				f.ChangeSummary = "The supported risk pattern persists with materially changed IAM context."
			}
			results = append(results, f)
		} else if len(bis) > 0 && len(ais) > 0 {
			for _, i := range bis {
				ambiguousBefore[i] = true
			}
			for _, i := range ais {
				ambiguousAfter[i] = true
			}
		}
	}

	for i, f := range after {
		if usedAfter[i] {
			continue
		}
		f.ChangeClassification = models.ChangeUnknown
		if !ambiguousAfter[i] && !f.ChangeUncertain && completeFor(f, "before", plan) {
			f.ChangeClassification = models.ChangeIntroduced
			f.ChangeSummary = "The supported risk pattern is absent from known before state and present in planned after state."
		} else {
			f.ChangeSummary = "Before-state context is incomplete or uncertain; introduction cannot be established."
		}
		results = append(results, f)
	}
	for i, f := range before {
		if usedBefore[i] {
			continue
		}
		f.ChangeClassification = models.ChangeUnknown
		if !ambiguousBefore[i] && !f.ChangeUncertain && completeFor(f, "after", plan) {
			f.ChangeClassification = models.ChangeResolved
			f.ChangeSummary = "The previously identified supported risk pattern is absent from known planned after state."
		} else {
			f.ChangeSummary = "After-state context is incomplete or uncertain; resolution cannot be established."
		}
		results = append(results, f)
	}

	for _, uncertainty := range plan.Uncertainties {
		results = append(results, models.Finding{
			RuleID: "terraform-analysis-unknown", Title: "Terraform IAM Analysis Unknown", Severity: "HIGH", Role: "unknown",
			Issue:           fmt.Sprintf("IAM analysis for %s state at %s is incomplete: %s", uncertainty.Side, uncertainty.Address, uncertainty.Reason),
			Impact:          "CloudAttack cannot establish whether supported IAM risk patterns are present or how they changed.",
			ResourceAddress: uncertainty.Address, ChangeClassification: models.ChangeUnknown,
			ChangeSummary: "Incomplete or unresolved Terraform IAM context prevents a reliable change classification.",
			IdentityRole:  uncertainty.Address, IdentitySubject: uncertainty.Side + "|" + uncertainty.Reason,
			Remediation: "Resolve the reported unknown or provide complete before and after Terraform plan context, then rerun the scan.",
		})
	}
	for i := range results {
		for _, change := range plan.Changes {
			if results[i].ResourceAddress == change.Address && change.PreviousAddress != "" {
				results[i].PreviousResourceAddress = change.PreviousAddress
				break
			}
		}
	}

	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Severity != results[j].Severity {
			return severityOrder(results[i].Severity) < severityOrder(results[j].Severity)
		}
		if results[i].ResourceAddress != results[j].ResourceAddress {
			return results[i].ResourceAddress < results[j].ResourceAddress
		}
		if results[i].RuleID != results[j].RuleID {
			return results[i].RuleID < results[j].RuleID
		}
		return results[i].ChangeClassification < results[j].ChangeClassification
	})
	return results
}

func indexFindings(findings []models.Finding, key func(models.Finding) string) map[string]int {
	result := map[string]int{}
	for i, finding := range findings {
		if k := key(finding); k != "" {
			result[k] = i
		}
	}
	return result
}

func groupFindingIndexes(findings []models.Finding, used []bool, key func(models.Finding) string) map[string][]int {
	result := map[string][]int{}
	for i, finding := range findings {
		if used[i] {
			continue
		}
		if k := key(finding); k != "" {
			result[k] = append(result[k], i)
		}
	}
	return result
}

func classifyPair(before, after models.Finding, plan models.TerraformPlan) models.Finding {
	result := after
	result.ChangeClassification = models.ChangeUnknown
	if before.ChangeUncertain || after.ChangeUncertain || !completeFor(before, "before", plan) || !completeFor(after, "after", plan) {
		result.ChangeSummary = "Relevant plan state or runtime condition context is incomplete; the change cannot be established."
		return result
	}
	if before.ContextFingerprint == after.ContextFingerprint {
		result.ChangeClassification = models.ChangeUnchanged
		result.ChangeSummary = "The supported risk pattern and its analyzed IAM context are unchanged."
	} else {
		result.ChangeClassification = models.ChangeChanged
		result.ChangeSummary = "The supported risk pattern persists with materially changed IAM context."
	}
	return result
}

func completeFor(f models.Finding, side string, plan models.TerraformPlan) bool {
	addresses := append([]string{}, f.RelatedAddresses...)
	addresses = append(addresses, f.ResourceAddress, f.RoleAddress)
	seen := map[string]bool{}
	for _, address := range addresses {
		if address == "" || seen[address] {
			continue
		}
		seen[address] = true
		known := false
		for _, change := range plan.Changes {
			matches := change.Address == address || (side == "before" && change.PreviousAddress == address)
			if !matches {
				continue
			}
			if side == "before" {
				known = change.BeforeKnown
			} else {
				known = change.AfterKnown
			}
			break
		}
		if !known {
			return false
		}
	}
	return len(seen) > 0
}

func canonicalAddress(address, side string, plan models.TerraformPlan) string {
	if side == "after" {
		for _, change := range plan.Changes {
			if change.Address == address && change.PreviousAddress != "" {
				return change.PreviousAddress
			}
		}
	}
	return address
}

func severityOrder(severity string) int {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	default:
		return 4
	}
}
