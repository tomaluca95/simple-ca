package caissuingprocess

import (
	"os"
	"os/user"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func gitAddAndCommitGitWorktree(
	gitWorktree *git.Worktree,
	msg string,
) error {
	thisHostname, err := os.Hostname()
	if err != nil {
		return err
	}
	currentUser, err := user.Current()
	if err != nil {
		return err
	}

	author := &object.Signature{
		Name:  currentUser.Name,
		Email: currentUser.Username + "@" + thisHostname,
		When:  time.Now(),
	}
	if _, err := gitWorktree.Add("."); err != nil {
		return err
	}

	gitStatus, err := gitWorktree.Status()
	if err != nil {
		return err
	}

	if !gitStatus.IsClean() {
		commit, err := gitWorktree.Commit(
			msg,
			&git.CommitOptions{
				Author: author,
			},
		)
		if err != nil {
			return err
		}
		_ = commit
	}
	return nil
}
