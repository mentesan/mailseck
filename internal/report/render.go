package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// ANSI foreground colors used to badge each severity level in
// RenderText. Foreground (not background) color was chosen deliberately:
// a background color's actual legibility depends on the terminal's
// color palette and the default foreground it pairs with, which varies
// per theme -- a background that reads fine on one terminal can turn
// into pale text on a matching-brightness background on another (e.g.
// white-on-yellow or white-on-blue on a dark theme). Colored, bold
// foreground text against whatever background the terminal already
// uses does not have that failure mode.
const (
	ansiReset  = "\033[0m"
	ansiInfoFG = "\033[36m"   // cyan
	ansiWarnFG = "\033[1;33m" // bold yellow
	ansiCritFG = "\033[1;31m" // bold red
)

// RenderText writes report to w as human-readable text: a domain header
// followed by one block per finding, each with a "[CRIT]"/"[WARN]"/
// "[INFO]" severity badge. The badge is colored with ANSI escape codes
// unless noColor is true or w is not an interactive terminal, so piping
// or redirecting output never leaves raw escape codes in the stream.
func RenderText(w io.Writer, report Report, noColor bool) error {
	useColor := shouldUseColor(w, noColor)

	if _, err := fmt.Fprintf(w, "SPF/DMARC report for %s\n\n", report.Domain); err != nil {
		return err
	}

	if len(report.Findings) == 0 {
		_, err := fmt.Fprintln(w, "No findings.")
		return err
	}

	for _, finding := range report.Findings {
		if _, err := fmt.Fprintf(w, "%s %s\n", severityBadge(finding.Severity, useColor), finding.Title); err != nil {
			return err
		}
		if finding.Detail == "" {
			continue
		}
		if _, err := fmt.Fprintf(w, "       %s\n", finding.Detail); err != nil {
			return err
		}
	}

	return nil
}

// shouldUseColor decides whether RenderText should emit ANSI color
// codes: never when noColor is true, and never when w is not an
// interactive terminal, regardless of noColor, since redirected or
// piped output should stay clean.
func shouldUseColor(w io.Writer, noColor bool) bool {
	return !noColor && isTerminal(w)
}

// isTerminal reports whether w is connected to an interactive terminal.
// It checks w's file mode directly, via os.ModeCharDevice, rather than
// pulling in a third-party isatty dependency, keeping this package free
// of external dependencies.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// severityBadge returns a fixed-width "[CRIT]"/"[WARN]"/"[INFO]" label,
// wrapped in an ANSI foreground color when useColor is true.
func severityBadge(severity Severity, useColor bool) string {
	label, fg := severityLabelAndColor(severity)
	if !useColor {
		return label
	}
	return fg + label + ansiReset
}

// severityLabelAndColor maps a Severity to its display label and ANSI
// foreground color. An unrecognized Severity value is treated as Info,
// so a malformed Finding still renders instead of panicking.
func severityLabelAndColor(severity Severity) (label, foreground string) {
	switch severity {
	case Crit:
		return "[CRIT]", ansiCritFG
	case Warn:
		return "[WARN]", ansiWarnFG
	default:
		return "[INFO]", ansiInfoFG
	}
}

// RenderJSON writes report to w as JSON, indented two spaces per level.
func RenderJSON(w io.Writer, report Report) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
