package caissuingprocess

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// gitCurrentUser is a variable so tests can stub an unresolvable user, the
// normal situation for the process user in a container image.
var gitCurrentUser = user.Current

// gitIgnoreFilename is the file that keeps the CA's working set out of the way
// of git. It is repository-relative.
const gitIgnoreFilename = ".gitignore"

// gitCRLIndexFilename is the repository-relative path of the revocation index,
// the record of which certificates this CA has revoked.
const gitCRLIndexFilename = "crl.yml"

// gitCertificatesDirName is the repository-relative directory the CA writes
// issued certificates into.
const gitCertificatesDirName = "crt"

// gitIgnoreContents is the data directory's .gitignore. Certificates and CSRs
// on disk are the CA's working set: git records one commit per operation and
// keeps every issued certificate reachable through the commit that added it,
// but it must not re-snapshot the whole certificate directory on every commit,
// which is what made the repository grow with the square of the certificates
// issued. The CA certificate stays visible because it is a file whose change
// matters.
func gitIgnoreContents(caCertificateRelPath string) string {
	return fmt.Sprintf(`# The CA working set: one commit per operation records the certificates that
# matter and keeps the rest reachable through history, so the whole directory
# is not tracked.
/%s/*
!/%s/%s
/csr/
`,
		gitCertificatesDirName,
		gitCertificatesDirName,
		filepath.Base(caCertificateRelPath),
	)
}

// gitIssueCommitMessage is the audit record for one issued certificate. It is
// the commit message, so the history names what each commit handed out even
// though the commit's tree holds only that one certificate.
//
// The record is a JSON object rather than plain text, so every value a CSR
// contributed -- the subject, the DNS names -- is JSON-escaped: a newline or
// other control character in a subject field stays a character inside one
// value and cannot forge lines of its own in the history. Serial and SHA256
// are strings, in the same shape the rest of the tool reports them.
func gitIssueCommitMessage(issuedCertificate *x509.Certificate) string {
	digest := sha256.Sum256(issuedCertificate.Raw)

	record := struct {
		Subject   string   `json:"subject"`
		Serial    string   `json:"serial"`
		DNSNames  []string `json:"dns_names,omitempty"`
		NotBefore string   `json:"not_before"`
		NotAfter  string   `json:"not_after"`
		SHA256    string   `json:"sha256"`
	}{
		Subject:   issuedCertificate.Subject.String(),
		Serial:    issuedCertificate.SerialNumber.String(),
		DNSNames:  issuedCertificate.DNSNames,
		NotBefore: issuedCertificate.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:  issuedCertificate.NotAfter.UTC().Format(time.RFC3339),
		SHA256:    hex.EncodeToString(digest[:]),
	}

	recordJSON, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		// The record holds only strings and a slice of strings, which cannot
		// fail to marshal. If a future field ever can, refuse to print a value
		// that was not escaped: the title alone still names the commit.
		return "issue certificate\n"
	}

	return "issue certificate\n\n" + string(recordJSON) + "\n"
}

// gitCommitStateWorktree records exactly the given repository-relative paths as
// a single commit. The index is reset first, so a path an earlier commit
// recorded and this one does not mention -- an older certificate, for instance --
// is absent from this commit's tree. That keeps every tree small no matter how
// many certificates the CA has issued, while the older files stay reachable
// through the history that added them.
//
// A change that leaves the tree untouched is not an error and is not committed.
func gitCommitStateWorktree(
	repo *git.Repository,
	gitWorktree *git.Worktree,
	msg string,
	paths []string,
) error {
	idx, err := repo.Storer.Index()
	if err != nil {
		return err
	}
	idx.Entries = nil
	if err := repo.Storer.SetIndex(idx); err != nil {
		return err
	}

	for _, path := range paths {
		// A named path that is not on disk yet is skipped: a commit records
		// what exists.
		if _, err := gitWorktree.Filesystem.Stat(filepath.ToSlash(path)); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		// SkipStatus is what keeps a commit cheap: the status of the whole
		// working tree is never computed, so a directory full of certificates
		// costs nothing here.
		if err := gitWorktree.AddWithOptions(&git.AddOptions{Path: path, SkipStatus: true}); err != nil {
			return err
		}
	}

	thisHostname, err := os.Hostname()
	if err != nil {
		return err
	}
	author := gitAuthorSignature(thisHostname)

	if _, err := gitWorktree.Commit(msg, &git.CommitOptions{Author: author}); err != nil {
		if errors.Is(err, git.ErrEmptyCommit) {
			return nil
		}
		return err
	}
	return nil
}

func gitAuthorSignature(hostname string) *object.Signature {
	author := &object.Signature{
		Email: hostname,
		When:  time.Now(),
	}
	if currentUser, err := gitCurrentUser(); err == nil {
		author.Name = currentUser.Name
		author.Email = currentUser.Username + "@" + hostname
	}
	return author
}
