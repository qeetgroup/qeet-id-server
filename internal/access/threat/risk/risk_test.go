package risk

import "testing"

func TestDeviceKey(t *testing.T) {
	cases := []struct {
		ua   string
		want string
	}{
		{ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36", want: "chrome-windows"},
		{ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15", want: "safari-macos"},
		{ua: "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/121.0", want: "firefox-linux"},
		{ua: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1", want: "safari-ios"},
		{ua: "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36", want: "chrome-android"},
		{ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/120.0.0.0", want: "edge-windows"},
		{ua: "", want: "other-other"},
	}
	for _, tc := range cases {
		if got := deviceKey(tc.ua); got != tc.want {
			t.Errorf("deviceKey(%q) = %q, want %q", tc.ua, got, tc.want)
		}
	}
}

func TestComputeLevel_BaseBotScoreOnly(t *testing.T) {
	settings := defaultSettings() // medium=0.50, high=0.80
	if l := computeLevel(settings, 0.0, false, false); l != Low {
		t.Errorf("botScore=0 = %v, want Low", l)
	}
	if l := computeLevel(settings, 0.55, false, false); l != Medium {
		t.Errorf("botScore=0.55 = %v, want Medium", l)
	}
	if l := computeLevel(settings, 0.95, false, false); l != High {
		t.Errorf("botScore=0.95 = %v, want High", l)
	}
}

func TestComputeLevel_ImpossibleTravelBumpsLevel(t *testing.T) {
	settings := defaultSettings()
	// Below both thresholds alone, but travel bump pushes it to High.
	got := computeLevel(settings, 0.35, true, false)
	if got != High {
		t.Errorf("botScore=0.35 + impossibleTravel = %v, want High (0.35+%.2f=%.2f)", got, impossibleTravelBump, 0.35+impossibleTravelBump)
	}
}

func TestComputeLevel_NewDeviceBumpsLevel(t *testing.T) {
	settings := defaultSettings()
	got := computeLevel(settings, 0.30, false, true)
	if got != Medium {
		t.Errorf("botScore=0.30 + newDevice = %v, want Medium (0.30+%.2f=%.2f)", got, newDeviceBump, 0.30+newDeviceBump)
	}
}

func TestComputeLevel_ScoreClampedToOne(t *testing.T) {
	settings := defaultSettings()
	// 0.95 (bot) + 0.5 (travel) + 0.25 (device) would exceed 1 unclamped;
	// must still resolve to a valid Level, not panic or misbehave.
	got := computeLevel(settings, 0.95, true, true)
	if got != High {
		t.Errorf("stacked signals = %v, want High", got)
	}
}

func TestComputeLevel_SignalsOffWhenFlagsFalse(t *testing.T) {
	settings := defaultSettings()
	withSignals := computeLevel(settings, 0.10, true, true)
	withoutSignals := computeLevel(settings, 0.10, false, false)
	if withSignals == withoutSignals {
		t.Errorf("expected travel+device bumps to change the level: with=%v without=%v", withSignals, withoutSignals)
	}
	if withoutSignals != Low {
		t.Errorf("botScore=0.10 alone = %v, want Low", withoutSignals)
	}
}
