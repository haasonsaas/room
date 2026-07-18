package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

type snapshot struct {
	directory   string
	config      string
	targetsFile string
	targets     []string
	lineCounts  map[string]int
}

func (a *adapter) createSnapshot(request analyzerRequest, artifact diffArtifact) (snapshot, error) {
	root, err := filepath.EvalSymlinks(a.repositoryRoot)
	if err != nil {
		return snapshot{}, err
	}
	workingDirectory, err := filepath.EvalSymlinks(request.WorkingDirectory)
	if err != nil {
		return snapshot{}, errors.New("working directory does not match repository root")
	}
	rootFD, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return snapshot{}, errors.New("repository root cannot be opened safely")
	}
	defer unix.Close(rootFD)
	workingFD, err := unix.Open(workingDirectory, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return snapshot{}, errors.New("working directory cannot be opened safely")
	}
	defer unix.Close(workingFD)
	var rootStat, workingStat unix.Stat_t
	if unix.Fstat(rootFD, &rootStat) != nil || unix.Fstat(workingFD, &workingStat) != nil || rootStat.Dev != workingStat.Dev || rootStat.Ino != workingStat.Ino {
		return snapshot{}, errors.New("working directory does not match repository root")
	}
	config, err := readRegularFile(a.config)
	if err != nil {
		return snapshot{}, err
	}
	configDigest := sha256.Sum256(config)
	if !strings.EqualFold(request.ConfigSHA256, hex.EncodeToString(configDigest[:])) {
		return snapshot{}, errors.New("Semgrep config digest changed")
	}
	temporary, err := os.MkdirTemp("", "room-semgrep-*")
	if err != nil {
		return snapshot{}, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(temporary)
		}
	}()
	repository := filepath.Join(temporary, "repository")
	if err := os.Mkdir(repository, 0o700); err != nil {
		return snapshot{}, err
	}
	configPath := filepath.Join(temporary, "rules.yml")
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		return snapshot{}, err
	}
	for path := range artifact.deleted {
		if err := requireMissingBeneath(rootFD, path); err != nil {
			return snapshot{}, err
		}
	}
	postimages := make(map[string][]byte, len(artifact.postimage))
	for path := range artifact.postimage {
		data, err := readRegularBeneath(rootFD, path)
		if err != nil {
			return snapshot{}, err
		}
		if err := verifyPostimage(data, artifact.expected[path]); err != nil {
			return snapshot{}, err
		}
		postimages[path] = data
	}
	targets := make([]string, 0, len(artifact.added))
	lineCounts := make(map[string]int, len(artifact.added))
	for path := range artifact.added {
		if !validRelativePath(path) {
			return snapshot{}, errors.New("diff path is invalid")
		}
		destination := filepath.Join(repository, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			return snapshot{}, err
		}
		postimage := postimages[path]
		if err := os.WriteFile(destination, postimage, 0o600); err != nil {
			return snapshot{}, err
		}
		lineCounts[path] = bytes.Count(postimage, []byte{'\n'})
		if len(postimage) > 0 && postimage[len(postimage)-1] != '\n' {
			lineCounts[path]++
		}
		targets = append(targets, path)
	}
	sort.Strings(targets)
	targetsPath := filepath.Join(temporary, "targets.json")
	targetManifest := []any{"Scanning_roots", map[string]any{
		"root_paths": targets,
		"targeting_conf": map[string]any{
			"exclude": []string{}, "max_target_bytes": 0,
			"respect_gitignore": false, "respect_semgrepignore_files": false,
			"always_select_explicit_targets": true, "explicit_targets": targets,
			"force_novcs_project": true, "exclude_minified_files": false,
		},
	}}
	targetJSON, err := json.Marshal(targetManifest)
	if err != nil {
		return snapshot{}, err
	}
	if err := os.WriteFile(targetsPath, targetJSON, 0o600); err != nil {
		return snapshot{}, err
	}
	cleanup = false
	return snapshot{directory: repository, config: configPath, targetsFile: targetsPath, targets: targets, lineCounts: lineCounts}, nil
}

func readRegularBeneath(rootFD int, path string) ([]byte, error) {
	fileFD, err := unix.Openat2(rootFD, filepath.FromSlash(path), &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return nil, errors.New("diff target cannot be opened safely")
	}
	return readRegularFD(fileFD, path, "diff target")
}

// readRegularFile reads an operator-owned absolute path without following a
// symlink at its final component.
func readRegularFile(path string) ([]byte, error) {
	fileFD, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	return readRegularFD(fileFD, path, path)
}

func readRegularFD(fileFD int, path, what string) ([]byte, error) {
	file := os.NewFile(uintptr(fileFD), path)
	defer file.Close()
	var before, after unix.Stat_t
	if err := unix.Fstat(fileFD, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size < 0 || before.Size > 64<<20 {
		return nil, fmt.Errorf("%s must be a regular file of at most 64 MiB", what)
	}
	data, err := io.ReadAll(io.LimitReader(file, before.Size+1))
	if err != nil || int64(len(data)) != before.Size {
		return nil, fmt.Errorf("%s changed while being read", what)
	}
	if err := unix.Fstat(fileFD, &after); err != nil || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return nil, fmt.Errorf("%s changed while being read", what)
	}
	return data, nil
}

func requireMissingBeneath(rootFD int, path string) error {
	fileFD, err := unix.Openat2(rootFD, filepath.FromSlash(path), &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	})
	if err == nil {
		_ = unix.Close(fileFD)
		return errors.New("deleted diff target still exists")
	}
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return errors.New("deleted diff target cannot be verified safely")
}
