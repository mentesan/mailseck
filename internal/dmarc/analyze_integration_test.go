//go:build integration

package dmarc

import (
	"context"
	"testing"
	"time"

	"github.com/mentesan/mailseck/internal/spf"
)

// TestAnalyzeIntegrationGmailCom exercises Analyze against a real,
// well-known domain over real DNS. It only runs with `go test -tags
// integration`, per this project's testing strategy (PRD.md §9): it
// depends on network access and on gmail.com continuing to publish a
// DMARC record, so it stays out of the default fast test run.
func TestAnalyzeIntegrationGmailCom(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resolver := spf.NewDNSResolver()
	result, err := Analyze(ctx, "gmail.com", resolver)
	if err != nil {
		t.Fatalf("Analyze() unexpected error: %v", err)
	}
	if !result.IsPresent {
		t.Fatal("IsPresent = false, want true: gmail.com is expected to publish a DMARC record")
	}
	if result.Policy == "" {
		t.Error("Policy is empty, want a published p= value")
	}

	t.Logf("gmail.com DMARC: %+v", result)
}
