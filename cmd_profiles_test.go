package main

import "testing"

func TestApplyProfilesFillsMissingProviderDefaults(t *testing.T) {
	applied, selectors, smtpPorts, smtpHosts, mdaPorts, mdaHosts, err := applyProfiles(
		[]string{"google-workspace"},
		nil,
		nil,
		nil,
		false,
		nil,
		nil,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 || applied[0] != "google-workspace" {
		t.Fatalf("applied = %#v", applied)
	}
	if len(selectors) == 0 || len(smtpHosts) == 0 || len(smtpPorts) == 0 || len(mdaHosts) == 0 || len(mdaPorts) == 0 {
		t.Fatalf("profile did not fill defaults: selectors=%#v smtpHosts=%#v smtpPorts=%#v mdaHosts=%#v mdaPorts=%#v", selectors, smtpHosts, smtpPorts, mdaHosts, mdaPorts)
	}
}

func TestApplyProfilesKeepsExplicitSMTPHost(t *testing.T) {
	_, _, _, smtpHosts, _, _, err := applyProfiles(
		[]string{"microsoft-365"},
		nil,
		[]string{"smtp.example.com"},
		nil,
		false,
		nil,
		nil,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(smtpHosts) != 1 || smtpHosts[0] != "smtp.example.com" {
		t.Fatalf("smtpHosts = %#v", smtpHosts)
	}
}

func TestApplyProfilesCombinesDefaultsFromMultipleProfiles(t *testing.T) {
	applied, selectors, smtpPorts, smtpHosts, _, _, err := applyProfiles(
		[]string{"google-workspace", "microsoft-365", "google-workspace"},
		nil,
		nil,
		nil,
		false,
		nil,
		nil,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 2 {
		t.Fatalf("applied = %#v", applied)
	}
	if len(smtpPorts) != 2 || smtpPorts[0] != 465 || smtpPorts[1] != 587 {
		t.Fatalf("smtpPorts = %#v", smtpPorts)
	}
	if len(smtpHosts) != 2 || len(selectors) == 0 {
		t.Fatalf("selectors=%#v smtpHosts=%#v", selectors, smtpHosts)
	}
}

func TestApplyProfilesRejectsUnknownProfile(t *testing.T) {
	_, _, _, _, _, _, err := applyProfiles([]string{"unknown"}, nil, nil, nil, false, nil, nil, false)
	if err == nil {
		t.Fatal("expected unknown profile error")
	}
}
