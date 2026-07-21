package anomaly

import "testing"

func TestScore_NewActionType(t *testing.T) {
	b := emptyBaseline()
	b.eventCount = 100
	b.actions["role.assigned"] = 100
	b.hours["14"] = 100

	sc, reasons := score(b, "billing.plan_changed", "", 14)
	if sc < weightAction {
		t.Errorf("score = %v, want >= %v (action novelty alone)", sc, weightAction)
	}
	if !contains(reasons, "new_action_type") {
		t.Errorf("reasons = %v, want new_action_type", reasons)
	}
}

func TestScore_FamiliarEverything(t *testing.T) {
	b := emptyBaseline()
	b.eventCount = 100
	b.actions["role.assigned"] = 100
	b.hours["14"] = 100
	b.ips["10.0.0.1"] = 100

	sc, reasons := score(b, "role.assigned", "10.0.0.1", 14)
	if sc != 0 {
		t.Errorf("score = %v, want 0 for fully familiar event", sc)
	}
	if len(reasons) != 0 {
		t.Errorf("reasons = %v, want none", reasons)
	}
}

func TestScore_NewIP(t *testing.T) {
	b := emptyBaseline()
	b.eventCount = 100
	b.actions["role.assigned"] = 100
	b.hours["14"] = 100
	b.ips["10.0.0.1"] = 100

	sc, reasons := score(b, "role.assigned", "203.0.113.5", 14)
	if sc != weightIP {
		t.Errorf("score = %v, want %v (IP novelty alone)", sc, weightIP)
	}
	if !contains(reasons, "new_ip") {
		t.Errorf("reasons = %v, want new_ip", reasons)
	}
}

func TestScore_UnusualHour(t *testing.T) {
	b := emptyBaseline()
	b.eventCount = 100
	b.actions["role.assigned"] = 100
	// All history at 14:00; never at 3am.
	b.hours["14"] = 100

	sc, reasons := score(b, "role.assigned", "", 3)
	if sc != weightHour {
		t.Errorf("score = %v, want %v (hour novelty alone)", sc, weightHour)
	}
	if !contains(reasons, "unusual_hour") {
		t.Errorf("reasons = %v, want unusual_hour", reasons)
	}
}

func TestScore_ClampedToOne(t *testing.T) {
	b := emptyBaseline() // zero history: everything is novel
	sc, _ := score(b, "billing.plan_changed", "203.0.113.5", 3)
	if sc > 1 {
		t.Errorf("score = %v, want <= 1", sc)
	}
}

func TestFold_UpdatesCounters(t *testing.T) {
	b := emptyBaseline()
	b = fold(b, "role.assigned", "10.0.0.1", 14)
	b = fold(b, "role.assigned", "10.0.0.1", 14)

	if b.eventCount != 2 {
		t.Errorf("eventCount = %d, want 2", b.eventCount)
	}
	if b.actions["role.assigned"] != 2 {
		t.Errorf("actions[role.assigned] = %d, want 2", b.actions["role.assigned"])
	}
	if b.hours["14"] != 2 {
		t.Errorf("hours[14] = %d, want 2", b.hours["14"])
	}
	if b.ips["10.0.0.1"] != 2 {
		t.Errorf("ips = %d, want 2", b.ips["10.0.0.1"])
	}
}

func TestFold_EmptyIPNotCounted(t *testing.T) {
	b := emptyBaseline()
	b = fold(b, "role.assigned", "", 14)
	if len(b.ips) != 0 {
		t.Errorf("ips = %v, want empty (no IP on this event)", b.ips)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
