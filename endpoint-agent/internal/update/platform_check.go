package update

import (
	"errors"
	"fmt"
	"strings"
)

// checkAuthenticode parses "<Status>|<Subject>" from Get-AuthenticodeSignature.
func checkAuthenticode(line, publisher string) error {
	status, subject, _ := strings.Cut(line, "|")
	if status != "Valid" {
		return fmt.Errorf("Authenticode status is %q, not Valid", status)
	}
	if publisher != "" && !strings.Contains(subject, publisher) {
		return fmt.Errorf("signed by %q, expected publisher %q", subject, publisher)
	}
	return nil
}

// checkCodesign parses `codesign -dv --verbose=2` output.
func checkCodesign(out, team string) error {
	if strings.Contains(out, "Signature=adhoc") {
		return errors.New("binary is only ad-hoc signed (no Developer ID)")
	}
	got := ""
	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "TeamIdentifier="); ok {
			got = v
		}
	}
	if got == "" || got == "not set" {
		return errors.New("binary has no TeamIdentifier")
	}
	if team != "" && got != team {
		return fmt.Errorf("TeamIdentifier %q, expected %q", got, team)
	}
	return nil
}
