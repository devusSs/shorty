// copied and adapted from
// https://github.com/shorty/shorty/blob/master/buildscripts/gen-ldflags.go
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func genLDFlags(version string) string {
	releaseTag, date := releaseTag(version)
	copyrightYear := strconv.Itoa(date.Year())
	ldflagsStr := "-s -w"
	ldflagsStr += " -X main.Version=" + version
	ldflagsStr += " -X main.CopyrightYear=" + copyrightYear
	ldflagsStr += " -X main.ReleaseTag=" + releaseTag
	ldflagsStr += " -X main.CommitID=" + commitID()
	ldflagsStr += " -X main.ShortCommitID=" + commitID()[:12]
	return ldflagsStr
}

// genReleaseTag prints release tag to the console for easy git tagging.
func releaseTag(version string) (string, time.Time) {
	relPrefix := "DEVELOPMENT"
	if prefix := os.Getenv("SHORTY_RELEASE"); prefix != "" {
		relPrefix = prefix
	}

	relSuffix := ""
	if hotfix := os.Getenv("SHORTY_HOTFIX"); hotfix != "" {
		relSuffix = hotfix
	}

	relTag := strings.ReplaceAll(version, " ", "-")
	relTag = strings.ReplaceAll(relTag, ":", "-")
	t, err := time.Parse("2006-01-02T15-04-05Z", relTag)
	if err != nil {
		panic(err)
	}

	relTag = strings.ReplaceAll(relTag, ",", "")
	relTag = relPrefix + "." + relTag
	if relSuffix != "" {
		relTag += "." + relSuffix
	}

	return relTag, t
}

// commitID returns the abbreviated commit-id hash of the last commit.
func commitID() string {
	// git log --format="%H" -n1
	var (
		commit []byte
		err    error
	)
	cmdName := "git"
	cmdArgs := []string{"log", "--format=%H", "-n1"}
	if commit, err = exec.Command(cmdName, cmdArgs...).Output(); err != nil {
		fmt.Fprintln(os.Stderr, "Error generating git commit-id: ", err)
		os.Exit(1)
	}

	return strings.TrimSpace(string(commit))
}

func commitTime() time.Time {
	// git log --format=%cD -n1
	var (
		commitUnix []byte
		err        error
	)
	cmdName := "git"
	cmdArgs := []string{"log", "--format=%cI", "-n1"}
	if commitUnix, err = exec.Command(cmdName, cmdArgs...).Output(); err != nil {
		fmt.Fprintln(os.Stderr, "Error generating git commit-time: ", err)
		os.Exit(1)
	}

	t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(commitUnix)))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error generating git commit-time: ", err)
		os.Exit(1)
	}

	return t.UTC()
}

func main() {
	var version string
	if len(os.Args) > 1 {
		version = os.Args[1]
	} else {
		version = commitTime().Format(time.RFC3339)
	}

	fmt.Println(genLDFlags(version))
}
