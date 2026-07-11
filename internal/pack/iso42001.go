package pack

// iso42001Set is the ISO/IEC 42001:2023 Annex A labels for the same evidence —
// the AI-management-system controls that have no automated evidence source in
// the GRC tools, which is exactly the gap this package fills. Control IDs and
// titles are verbatim from the standard's Annex A; they travel inside the signed
// package, so an auditor reads them against the standard text. The three Annex A
// controls crossbearing's join speaks to directly:
//
//	A.3.2   — AI roles and responsibilities. Accountability for what the AI does
//	          is to be defined and allocated; an action bound to no named human is
//	          the gap where that accountability isn't enforced operationally.
//	A.6.2.8 — AI system recording of event logs. The corroboration is against the
//	          system's own recorded event logs; unrecorded/unclaimed findings are
//	          the recording gaps that control exists to catch.
//	A.6.2.6 — AI system operation and monitoring. Reconciling recorded operation
//	          against the agent's own account is the monitoring; mismatches and
//	          unclaimed production changes are the signal.
//
// Each carries the same finding role as its SOC 2 counterpart (A.3.2↔CC6.1,
// A.6.2.8↔CC7.2, A.6.2.6↔CC8.1) — the frameworks express that role through
// different control intents (organizational accountability vs logical access,
// etc.), not identical controls.
func iso42001Set() *controlSet {
	const fw = "ISO/IEC 42001:2023"
	return &controlSet{
		attribution: ControlMapping{Framework: fw, Control: "A.3.2",
			Name:      "AI roles and responsibilities",
			Statement: "agent actions bound (or provably not bindable) to a named human accountable for them"},
		monitoring: ControlMapping{Framework: fw, Control: "A.6.2.8",
			Name:      "AI system recording of event logs",
			Statement: "agent actions present and corroborated in the recorded event logs; recording gaps surfaced"},
		change: ControlMapping{Framework: fw, Control: "A.6.2.6",
			Name:      "AI system operation and monitoring",
			Statement: "recorded AI-system operation reconciled against the agent's own account; divergences surfaced"},
	}
}
