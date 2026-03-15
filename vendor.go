package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// CLIInfo describes the resolved CLI binary.
type CLIInfo struct {
	Path    string // absolute path to the binary
	Version string // output of `vulnetix version --short`
	Source  string // "vendored", "sibling", "PATH"
}

// ghRelease is the subset of GitHub's release JSON we need.
type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// ensureCLI checks for a vendored CLI binary, offers to install/update it if
// missing or stale, and returns the resolved CLIInfo. This runs BEFORE
// BubbleTea starts, so stdin is available for interactive prompts.
func ensureCLI(projectDir string) CLIInfo {
	binDir := filepath.Join(projectDir, "bin")
	vendoredPath := filepath.Join(binDir, "vulnetix")

	// Check if vendored binary exists and is fresh (< 24h)
	if info, err := os.Stat(vendoredPath); err == nil {
		age := time.Since(info.ModTime())
		if age < 24*time.Hour {
			ver := getCLIVersion(vendoredPath)
			return CLIInfo{Path: vendoredPath, Version: ver, Source: "vendored"}
		}
		// Stale — offer update
		currentVer := getCLIVersion(vendoredPath)
		return offerUpdate(vendoredPath, binDir, currentVer, age)
	}

	// No vendored binary — offer fresh install
	return offerInstall(vendoredPath, binDir)
}

func offerInstall(vendoredPath, binDir string) CLIInfo {
	rel, err := fetchLatestRelease()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not check CLI releases: %s\n", err)
		return fallbackCLI(vendoredPath)
	}

	platform := runtime.GOOS + "/" + runtime.GOARCH
	assetName := cliAssetName()
	asset := findAsset(rel.Assets, assetName)
	if asset == nil {
		fmt.Fprintf(os.Stderr, "No CLI binary for %s in release %s\n", platform, rel.TagName)
		return fallbackCLI(vendoredPath)
	}

	fmt.Fprintf(os.Stderr, "\nVulnetix CLI Installation\n")
	fmt.Fprintf(os.Stderr, "  Release:  %s\n", rel.TagName)
	fmt.Fprintf(os.Stderr, "  Platform: %s\n", platform)
	fmt.Fprintf(os.Stderr, "  Asset:    %s\n", assetName)
	fmt.Fprintf(os.Stderr, "  Install:  %s\n\n", vendoredPath)
	fmt.Fprintf(os.Stderr, "Install? [Y/n] ")

	if !promptYes() {
		return fallbackCLI(vendoredPath)
	}

	if err := os.MkdirAll(binDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create bin dir: %s\n", err)
		return fallbackCLI(vendoredPath)
	}

	fmt.Fprintf(os.Stderr, "Downloading vulnetix CLI %s... ", rel.TagName)
	if err := downloadLatestCLI(vendoredPath, asset.BrowserDownloadURL); err != nil {
		fmt.Fprintf(os.Stderr, "failed: %s\n", err)
		return fallbackCLI(vendoredPath)
	}
	fmt.Fprintf(os.Stderr, "done\n\n")

	ver := getCLIVersion(vendoredPath)
	return CLIInfo{Path: vendoredPath, Version: ver, Source: "vendored"}
}

func offerUpdate(vendoredPath, binDir, currentVer string, age time.Duration) CLIInfo {
	rel, err := fetchLatestRelease()
	if err != nil {
		// Can't check — use stale binary
		return CLIInfo{Path: vendoredPath, Version: currentVer, Source: "vendored"}
	}

	assetName := cliAssetName()
	asset := findAsset(rel.Assets, assetName)
	if asset == nil {
		return CLIInfo{Path: vendoredPath, Version: currentVer, Source: "vendored"}
	}

	// If versions match, just touch the file to reset the 24h timer
	latestVer := rel.TagName
	if currentVer != "" && strings.TrimPrefix(latestVer, "v") == strings.TrimPrefix(currentVer, "v") {
		os.Chtimes(vendoredPath, time.Now(), time.Now())
		return CLIInfo{Path: vendoredPath, Version: currentVer, Source: "vendored"}
	}

	platform := runtime.GOOS + "/" + runtime.GOARCH
	fmt.Fprintf(os.Stderr, "\nVulnetix CLI Update Available\n")
	fmt.Fprintf(os.Stderr, "  Current:  %s (installed %s ago)\n", currentVer, formatAge(age))
	fmt.Fprintf(os.Stderr, "  Latest:   %s\n", latestVer)
	fmt.Fprintf(os.Stderr, "  Platform: %s\n\n", platform)
	fmt.Fprintf(os.Stderr, "Update? [Y/n] ")

	if !promptYes() {
		os.Chtimes(vendoredPath, time.Now(), time.Now())
		return CLIInfo{Path: vendoredPath, Version: currentVer, Source: "vendored"}
	}

	fmt.Fprintf(os.Stderr, "Downloading vulnetix CLI %s... ", latestVer)
	if err := downloadLatestCLI(vendoredPath, asset.BrowserDownloadURL); err != nil {
		fmt.Fprintf(os.Stderr, "failed: %s\n", err)
		return CLIInfo{Path: vendoredPath, Version: currentVer, Source: "vendored"}
	}
	fmt.Fprintf(os.Stderr, "done\n\n")

	ver := getCLIVersion(vendoredPath)
	return CLIInfo{Path: vendoredPath, Version: ver, Source: "vendored"}
}

func fallbackCLI(vendoredPath string) CLIInfo {
	// Try vendored (even stale)
	if _, err := os.Stat(vendoredPath); err == nil {
		ver := getCLIVersion(vendoredPath)
		return CLIInfo{Path: vendoredPath, Version: ver, Source: "vendored"}
	}

	// Try sibling repo
	dir := filepath.Dir(filepath.Dir(vendoredPath)) // up from bin/
	sibling := filepath.Join(dir, "..", "cli", "bin", "vulnetix")
	if abs, err := filepath.Abs(sibling); err == nil {
		if _, err := os.Stat(abs); err == nil {
			ver := getCLIVersion(abs)
			return CLIInfo{Path: abs, Version: ver, Source: "sibling"}
		}
	}

	// Try PATH
	if p, err := exec.LookPath("vulnetix"); err == nil {
		ver := getCLIVersion(p)
		return CLIInfo{Path: p, Version: ver, Source: "PATH"}
	}

	return CLIInfo{Path: "vulnetix", Version: "", Source: "not found"}
}

func fetchLatestRelease() (*ghRelease, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/repos/Vulnetix/cli/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	return &rel, nil
}

func cliAssetName() string {
	name := fmt.Sprintf("vulnetix-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

func findAsset(assets []ghAsset, name string) *ghAsset {
	for i := range assets {
		if assets[i].Name == name {
			return &assets[i]
		}
	}
	return nil
}

func downloadLatestCLI(destPath, downloadURL string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Write to temp file in same directory for atomic rename
	dir := filepath.Dir(destPath)
	tmpFile, err := os.CreateTemp(dir, ".vulnetix-download-*")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath) // clean up on failure

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		tmpFile.Close()
		return err
	}
	tmpFile.Close()

	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return err
	}

	return os.Rename(tmpPath, destPath)
}

func getCLIVersion(cliPath string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, cliPath, "version", "--short")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func promptYes() bool {
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "" || line == "y" || line == "yes"
}

func formatAge(d time.Duration) string {
	if d < time.Hour {
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%d hours", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}
