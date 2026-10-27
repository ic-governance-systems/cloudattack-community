package formatter

import "cloudattack-community/internal/models"

func findingEvidencePtr(evidence models.FindingEvidence) *models.FindingEvidence {
	if evidence.RoleReference == "" && evidence.PolicyReference == "" && len(evidence.PrincipalReferences) == 0 && len(evidence.ActionPatterns) == 0 && len(evidence.ResourcePatterns) == 0 && !evidence.ConditionPresent {
		return nil
	}
	return &evidence
}
