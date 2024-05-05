package caissuingprocess

import (
	"errors"

	"github.com/go-git/go-git/v5"
)

func gitOpenRepository(
	dataDir string,
) (*git.Worktree, error) {
	var repoGit *git.Repository
	{
		r, err := git.PlainOpen(dataDir)
		if err != nil {
			if errors.Is(err, git.ErrRepositoryNotExists) {
				newR, err := git.PlainInit(dataDir, false)
				if err != nil {
					return nil, err
				}
				repoGit = newR
			} else {
				return nil, err
			}
		} else {
			repoGit = r
		}
	}
	gitWorktree, err := repoGit.Worktree()
	if err != nil {
		return nil, err
	}
	return gitWorktree, nil
}
