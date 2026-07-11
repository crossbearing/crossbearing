package pack

import (
	"github.com/crossbearing/crossbearing/internal/attribute"
	"github.com/crossbearing/crossbearing/internal/corroborate"
)

// ControlMapping ties package contents to one control in a compliance
// framework. The mapping is static and deliberately small: each entry must
// survive an auditor asking "why does this finding speak to this control?" —
// a defensible few are worth more than an impressive many.
type ControlMapping struct {
	Framework string `json:"framework"` // "SOC 2 (TSC)", "ISO/IEC 42001:2023"
	Control   string `json:"control"`   // "CC6.1", "A.9.2"
	Name      string `json:"name"`
	// Statement says what the package contents demonstrate or contradict for
	// this control, in one sentence.
	Statement string `json:"statement"`
	// FindingIndexes point into Package.Findings.
	FindingIndexes []int `json:"findingIndexes,omitempty"`
	// ConventionRoles lists roles whose trust-policy gaps speak to this control.
	ConventionRoles []string `json:"conventionRoles,omitempty"`
}

// A controlSet is the same three evidentiary roles in one framework's labels:
//
//	attribution — actions must be attributable to an identified human.
//	              Unattributed findings and anonymous-by-default role conventions
//	              are direct evidence.
//	monitoring  — the corroboration join IS a monitoring / event-logging control;
//	              corroborated findings show it operating, unclaimed/unrecorded
//	              findings are what it surfaced.
//	change      — divergence between claimed and recorded changes (mismatches,
//	              production-touching unclaimed records) is evidence about
//	              authorized, tracked operation.
//
// SOC 2 and ISO/IEC 42001 map the SAME findings to their analogous controls, so
// the classification runs once (classify) and fills both sets.
type controlSet struct {
	attribution, monitoring, change ControlMapping
}

func (s *controlSet) all() []ControlMapping {
	return []ControlMapping{s.attribution, s.monitoring, s.change}
}

func (s *controlSet) classify(cf ChainedFinding) {
	switch cf.Finding.Kind {
	case corroborate.Unattributed:
		s.attribution.FindingIndexes = append(s.attribution.FindingIndexes, cf.Index)
	case corroborate.Corroborated, corroborate.UnrecordedClaim:
		s.monitoring.FindingIndexes = append(s.monitoring.FindingIndexes, cf.Index)
	case corroborate.UnclaimedRecord:
		s.monitoring.FindingIndexes = append(s.monitoring.FindingIndexes, cf.Index)
		if cf.Finding.Record != nil && cf.Finding.Record.ProductionTouching {
			s.change.FindingIndexes = append(s.change.FindingIndexes, cf.Index)
		}
	case corroborate.Mismatch:
		s.change.FindingIndexes = append(s.change.FindingIndexes, cf.Index)
	}
}

func (s *controlSet) addConventionRole(role string) {
	s.attribution.ConventionRoles = append(s.attribution.ConventionRoles, role)
}

// mapControls classifies every finding once and emits the control mappings for
// each supported framework. Every control ships, populated or not — "nothing
// spoke to this control in this window" is itself an auditable statement.
func mapControls(findings []ChainedFinding, conventions []attribute.RoleConventions) []ControlMapping {
	sets := []*controlSet{soc2Set(), iso42001Set()}
	for _, cf := range findings {
		for _, s := range sets {
			s.classify(cf)
		}
	}
	for _, rc := range conventions {
		if len(rc.Gaps()) > 0 {
			for _, s := range sets {
				s.addConventionRole(rc.RoleARN)
			}
		}
	}
	var out []ControlMapping
	for _, s := range sets {
		out = append(out, s.all()...)
	}
	return out
}

// soc2Set is the SOC 2 Common Criteria (AICPA Trust Services Criteria) labels —
// the same IDs Vanta and Drata track, so the package attaches to those controls
// with no translation.
//
//	CC6.1 — logical access: actions attributable to identified principals.
//	CC7.2 — system monitoring: the corroboration join, operating and surfacing anomalies.
//	CC8.1 — change management: claimed vs recorded changes reconciled.
func soc2Set() *controlSet {
	const fw = "SOC 2 (TSC)"
	return &controlSet{
		attribution: ControlMapping{Framework: fw, Control: "CC6.1",
			Name:      "Logical and physical access controls — identification and attribution",
			Statement: "agent actions bound (or provably not bindable) to named humans"},
		monitoring: ControlMapping{Framework: fw, Control: "CC7.2",
			Name:      "System monitoring — anomaly detection",
			Statement: "agent claims corroborated against infrastructure records; divergences surfaced"},
		change: ControlMapping{Framework: fw, Control: "CC8.1",
			Name:      "Change management — authorized and tracked changes",
			Statement: "recorded changes reconciled against the actor's own account of them"},
	}
}
