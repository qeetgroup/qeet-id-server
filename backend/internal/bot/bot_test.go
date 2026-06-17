package bot

import "testing"

func TestScore(t *testing.T) {
	chrome := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
	cases := []struct {
		name string
		ua   string
		want func(float64) bool
	}{
		{"empty UA is strongly bot-like", "", func(s float64) bool { return s >= 0.8 }},
		{"curl signature is conclusive", "curl/8.4.0", func(s float64) bool { return s >= 0.9 }},
		{"python-requests signature", "python-requests/2.31.0", func(s float64) bool { return s >= 0.9 }},
		{"headless chrome", "Mozilla/5.0 HeadlessChrome/124.0", func(s float64) bool { return s >= 0.9 }},
		{"non-browser UA is mildly suspicious", "PostmanRuntime/7.32", func(s float64) bool { return s >= 0.3 && s < 0.9 }},
		{"ordinary chrome scores zero", chrome, func(s float64) bool { return s == 0 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Score(c.ua); !c.want(got) {
				t.Errorf("Score(%q) = %v, outside expected range", c.ua, got)
			}
		})
	}
}
