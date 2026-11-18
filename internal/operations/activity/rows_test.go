package activity

import (
	"testing"

	"github.com/google/uuid"
)

// TestEventsDescribeTheirDeviceAndPlace checks that an event names the
// browser, operating system and device type from its user agent, and its
// country, city and place from where its metadata says it came from.
func TestEventsDescribeTheirDeviceAndPlace(t *testing.T) {
	iphone := "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
	ev := mapAuditRow(auditRow{ID: uuid.New(), Action: "auth.login_succeeded", UserAgent: &iphone,
		Metadata: []byte(`{"geo":{"country":"IN","city":"Pune"}}`)})
	if ev.Browser == nil || *ev.Browser != "Safari" || ev.OS == nil || *ev.OS != "iOS" || ev.Device == nil || *ev.Device != "mobile" {
		t.Errorf("an iPhone's event: browser %v, os %v, device %v", ev.Browser, ev.OS, ev.Device)
	}
	if ev.Country == nil || *ev.Country != "IN" || ev.City == nil || *ev.City != "Pune" || ev.Location == nil || *ev.Location != "Pune, IN" {
		t.Errorf("a placed event: country %v, city %v, location %v", ev.Country, ev.City, ev.Location)
	}
	curl := "curl/8.4.0"
	ev = mapAuditRow(auditRow{ID: uuid.New(), Action: "auth.login_succeeded", UserAgent: &curl})
	if ev.Browser == nil || *ev.Browser != "curl" || ev.OS != nil || ev.Device != nil || ev.Location != nil {
		t.Errorf("a curl event: browser %v, os %v, device %v, location %v", ev.Browser, ev.OS, ev.Device, ev.Location)
	}
}

// TestMapAuditRowOrganizationID checks that mapAuditRow copies the row's OrganizationID.
func TestMapAuditRowOrganizationID(t *testing.T) {
	organizationID := uuid.New()
	row := auditRow{
		ID:             uuid.New(),
		Action:         "user.created",
		OrganizationID: organizationID,
	}
	ev := mapAuditRow(row)
	if ev.OrganizationID != organizationID {
		t.Errorf("OrganizationID = %v, want %v", ev.OrganizationID, organizationID)
	}
}
