package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeyInputsFromFileAndStdin(t *testing.T) {
	signingKey := strings.Repeat("ab", 32)
	signingFile := filepath.Join(t.TempDir(), "signing-key")
	if err := os.WriteFile(signingFile, []byte(signingKey+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := readSigningKey(signingFile); got != signingKey {
		t.Fatal("signing key file was not read")
	}

	scopeKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	scopeFile := filepath.Join(t.TempDir(), "scope-key")
	if err := os.WriteFile(scopeFile, []byte(scopeKey+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := readKey(scopeFile, "key"); got != scopeKey {
		t.Fatal("scope key file was not read")
	}

	originalStdin := os.Stdin
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		os.Stdin = originalStdin
		reader.Close()
	})
	os.Stdin = reader
	if _, err := writer.WriteString(signingKey + "\n"); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	if got := readSigningKey("-"); got != signingKey {
		t.Fatal("signing key stdin was not read")
	}
}
