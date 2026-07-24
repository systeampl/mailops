package main

import "testing"

func TestParsePorts(t *testing.T) {
	got, err := parsePorts([]string{"25", "587", "25"}, []int{25})
	if err != nil {
		t.Fatal(err)
	}
	want := []int{25, 587}
	if len(got) != len(want) {
		t.Fatalf("ports = %#v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ports = %#v", got)
		}
	}
}

func TestParsePortsDefault(t *testing.T) {
	got, err := parsePorts(nil, []int{143, 993})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != 143 || got[1] != 993 {
		t.Fatalf("ports = %#v", got)
	}
}

func TestParsePortsRejectsInvalidValues(t *testing.T) {
	for _, value := range []string{"invalid", "0", "65536"} {
		if _, err := parsePorts([]string{value}, nil); err == nil {
			t.Fatalf("parsePorts(%q) succeeded", value)
		}
	}
}
