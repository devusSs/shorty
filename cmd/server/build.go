package main

import "fmt"

var (
	Version       string
	CopyrightYear string
	ReleaseTag    string
	CommitID      string
	ShortCommitID string
)

type Build struct {
	Version       string `json:"version"`
	CopyrightYear string `json:"copyright_year"`
	ReleaseTag    string `json:"release_tag"`
	CommitID      string `json:"commit_id"`
	ShortCommitID string `json:"short_commit_id"`
}

func (b *Build) String() string {
	return fmt.Sprintf("%+v", *b)
}

func getBuild() *Build {
	return &Build{
		Version:       Version,
		CopyrightYear: CopyrightYear,
		ReleaseTag:    ReleaseTag,
		CommitID:      CommitID,
		ShortCommitID: ShortCommitID,
	}
}
