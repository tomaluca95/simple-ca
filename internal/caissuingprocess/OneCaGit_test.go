package caissuingprocess_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/tomaluca95/simple-ca/internal/caissuingprocess"
	"github.com/tomaluca95/simple-ca/internal/pemhelper"
	"github.com/tomaluca95/simple-ca/internal/types"
)

// The data repository records one commit per operation. Each commit's tree must
// stay small -- it holds the CA certificate, the revocation index and the one
// certificate that operation issued -- while every certificate stays reachable
// through the commit that added it. Otherwise the tree would grow with the
// square of the certificates issued, which is PERF-1.
func TestRsaGitHistoryIsBoundedPerCommitAndKeepsEveryCertificate(t *testing.T) {
	logger := &types.StdLogger{}

	dataDirectory := t.TempDir()
	caId := "test_ca_1"

	configData := types.CertificateAuthorityType{
		Subject: types.CertificateAuthoritySubjectType{
			CommonName: "test_ca_1",
		},
		KeyConfig: types.KeyConfigType{
			Type:   "rsa",
			Config: types.KeyTypeRsaConfigType{Size: 2048},
		},
		CrlTtl:            12 * time.Hour,
		Validity:          testCaValidity,
		PermittedIPRanges: []string{"0.0.0.0/0"},
		ExcludedIPRanges:  []string{"0.0.0.0/0"},
	}
	ca, err := caissuingprocess.LoadOneCa(
		context.Background(),
		logger,
		caId,
		dataDirectory,
		configData,
	)
	if err != nil {
		t.Fatal(err)
	}

	const issuedCount = 8
	spoolDir := filepath.Join(dataDirectory, caId, "data", "csr")
	issuedSerials := []string{}
	for i := 0; i < issuedCount; i++ {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: fmt.Sprintf("host%d.example.com", i)},
		}, key)
		if err != nil {
			t.Fatal(err)
		}
		csrFilename := filepath.Join(spoolDir, fmt.Sprintf("host%d.csr.pem", i))
		if err := os.WriteFile(csrFilename, pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE REQUEST", Bytes: csrDER,
		}), 0o644); err != nil {
			t.Fatal(err)
		}

		pemBytes, err := ca.SignCsrFile(
			context.Background(),
			csrFilename,
			nil,
			func(ctx context.Context, proposedCertificate *x509.Certificate) error { return nil },
		)
		if err != nil {
			t.Fatal(err)
		}
		issuedCertificate, err := pemhelper.FromPemToCertificate(pemBytes)
		if err != nil {
			t.Fatal(err)
		}
		issuedSerials = append(issuedSerials, issuedCertificate.SerialNumber.String())
	}

	repo, err := git.PlainOpen(filepath.Join(dataDirectory, caId, "data"))
	if err != nil {
		t.Fatal(err)
	}

	// Walk the history: every commit's tree stays bounded, and every issued
	// certificate is present in the tree of the commit that added it.
	reachable := map[string]bool{}
	largestTree := 0
	logIter, err := repo.Log(&git.LogOptions{})
	if err != nil {
		t.Fatal(err)
	}
	err = logIter.ForEach(func(commit *object.Commit) error {
		tree, err := commit.Tree()
		if err != nil {
			return err
		}
		fileCount := 0
		err = tree.Files().ForEach(func(file *object.File) error {
			fileCount++
			if strings.HasPrefix(file.Name, "crt/") && strings.HasSuffix(file.Name, ".crt.pem") {
				reachable[filepath.Base(file.Name)] = true
			}
			return nil
		})
		if err != nil {
			return err
		}
		if fileCount > largestTree {
			largestTree = fileCount
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// The CA certificate, .gitignore, crl.yml, and at most the one certificate
	// this operation issued: four files, whether 8 certificates have been
	// issued or 8,000.
	if largestTree > 4 {
		t.Fatalf("a commit's tree must not grow with the certificates issued, largest was %d files", largestTree)
	}

	// Every certificate issued is reachable in the history, plus the CA
	// certificate itself.
	caCertificateReachable := false
	for name := range reachable {
		if name == caSerialName(t, ca) {
			caCertificateReachable = true
		}
	}
	if !caCertificateReachable {
		t.Errorf("the CA certificate must be reachable in history")
	}
	for _, serial := range issuedSerials {
		if !reachable[serial+".crt.pem"] {
			t.Errorf("issued certificate %s must be reachable in history", serial)
		}
	}

	// The working tree is not noise: the on-disk certificates are ignored and
	// the commit's own files are unmodified.
	worktree, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	status, err := worktree.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !status.IsClean() {
		t.Fatalf("the data repository must stay clean, got:\n%s", status)
	}
}

func caSerialName(t *testing.T, ca *caissuingprocess.OneCaType) string {
	t.Helper()
	caCertificatePem, err := ca.GetIssuerPem()
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := pemhelper.FromPemToCertificate(caCertificatePem)
	if err != nil {
		t.Fatal(err)
	}
	return caCertificate.SerialNumber.String() + ".crt.pem"
}
