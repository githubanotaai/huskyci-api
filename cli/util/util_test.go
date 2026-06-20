// Copyright 2019 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package util

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// createTempFiles creates files with given names and content in the specified directory.
func createTempFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("failed to create test file %s: %v", name, err)
		}
	}
}

// verifyZipContents checks that a zip file at zipPath contains all the expected file entries.
func verifyZipContents(t *testing.T, zipPath string, expectedFiles []string) {
	t.Helper()
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("failed to open zip: %v", err)
	}
	defer r.Close()

	found := make(map[string]bool)
	for _, f := range r.File {
		found[f.Name] = true
	}

	for _, expected := range expectedFiles {
		if !found[expected] {
			t.Errorf("expected file %q not found in zip (found: %v)", expected, found)
		}
	}
}

func TestGetAllAllowedFilesAndDirsFromPath(t *testing.T) {
	t.Parallel()

	t.Run("happy path with mixed files", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		createTempFiles(t, dir, map[string]string{
			"main.go":     "package main",
			"README.md":   "# README",
			"config.yaml": "key: value",
		})

		files, err := GetAllAllowedFilesAndDirsFromPath(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(files) != 3 {
			t.Fatalf("expected 3 files, got %d: %v", len(files), files)
		}
	})

	t.Run("excludes image and video extensions", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		createTempFiles(t, dir, map[string]string{
			"code.go":   "package main",
			"photo.jpg": "fake jpg",
			"video.mp4": "fake mp4",
			"script.sh": "#!/bin/sh",
			"image.png": "fake png",
			"movie.mov": "fake mov",
			"logo.svg":  "fake svg",
			"doc.pdf":   "fake pdf",
		})

		files, err := GetAllAllowedFilesAndDirsFromPath(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Only code.go and script.sh should be included (extensions not in blocklist)
		expected := map[string]bool{"code.go": true, "script.sh": true}
		for _, f := range files {
			if !expected[f] {
				t.Errorf("unexpected file included: %s", f)
			}
		}
		if len(files) != 2 {
			t.Errorf("expected 2 files, got %d: %v", len(files), files)
		}
	})

	t.Run("excludes additional image extensions", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		createTempFiles(t, dir, map[string]string{
			"source.go":  "package main",
			"img.jpeg":   "fake jpeg",
			"img.gif":    "fake gif",
			"img.webp":   "fake webp",
			"img.bmp":    "fake bmp",
			"video.avi":  "fake avi",
			"video.webm": "fake webm",
			"video.flv":  "fake flv",
		})

		files, err := GetAllAllowedFilesAndDirsFromPath(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(files) != 1 {
			t.Errorf("expected 1 file (source.go), got %d: %v", len(files), files)
		}
		if len(files) > 0 && files[0] != "source.go" {
			t.Errorf("expected source.go, got %s", files[0])
		}
	})

	t.Run("empty directory", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()

		files, err := GetAllAllowedFilesAndDirsFromPath(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(files) != 0 {
			t.Errorf("expected 0 files, got %d", len(files))
		}
	})

	t.Run("non-existent directory", func(t *testing.T) {
		t.Parallel()
		_, err := GetAllAllowedFilesAndDirsFromPath("/nonexistent/path/12345")
		if err == nil {
			t.Fatal("expected error for non-existent directory")
		}
	})

	t.Run("includes directories and files without extensions", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		createTempFiles(t, dir, map[string]string{
			"main.go":    "package main",
			"Makefile":   "all: build",
			"Dockerfile": "FROM alpine",
		})
		subdir := filepath.Join(dir, "subpkg")
		if err := os.Mkdir(subdir, 0750); err != nil {
			t.Fatalf("failed to create subdir: %v", err)
		}

		files, err := GetAllAllowedFilesAndDirsFromPath(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// main.go (allowed), Makefile (no ext, allowed), Dockerfile (no ext, allowed), subpkg (dir, allowed)
		if len(files) != 4 {
			t.Errorf("expected 4 entries, got %d: %v", len(files), files)
		}
	})
}

// TestCompressFiles does NOT use t.Parallel() because it modifies HOME and CWD.
func TestCompressFiles(t *testing.T) {
	t.Run("creates valid zip with file entries", func(t *testing.T) {
		homeDir := t.TempDir()

		// Override HOME so config.GetHuskyZipFilePath writes to a temp location.
		t.Setenv("HOME", homeDir)

		// Create test files in the home directory.
		createTempFiles(t, homeDir, map[string]string{
			"main.go":   "package main\nfunc main() {}",
			"README.md": "# Test Project",
		})

		// Change to home directory so archiver resolves relative names correctly.
		oldWd, err := os.Getwd()
		if err != nil {
			t.Fatalf("failed to get cwd: %v", err)
		}
		if err := os.Chdir(homeDir); err != nil {
			t.Fatalf("failed to chdir: %v", err)
		}
		defer func() {
			if err := os.Chdir(oldWd); err != nil {
				t.Errorf("failed to restore cwd: %v", err)
			}
		}()

		files, err := GetAllAllowedFilesAndDirsFromPath(homeDir)
		if err != nil {
			t.Fatalf("GetAllAllowedFilesAndDirsFromPath failed: %v", err)
		}
		if len(files) == 0 {
			t.Fatal("expected at least one file")
		}

		zipPath, err := CompressFiles(files)
		if err != nil {
			t.Fatalf("CompressFiles failed: %v", err)
		}

		verifyZipContents(t, zipPath, files)
	})

	t.Run("preserves directory structure", func(t *testing.T) {
		homeDir := t.TempDir()

		t.Setenv("HOME", homeDir)

		// Create nested directory structure.
		subDir := filepath.Join(homeDir, "subpkg")
		if err := os.Mkdir(subDir, 0750); err != nil {
			t.Fatalf("failed to create subdir: %v", err)
		}
		createTempFiles(t, homeDir, map[string]string{
			"main.go": "package main",
		})
		createTempFiles(t, subDir, map[string]string{
			"helper.go": "package subpkg",
		})

		oldWd, err := os.Getwd()
		if err != nil {
			t.Fatalf("failed to get cwd: %v", err)
		}
		if err := os.Chdir(homeDir); err != nil {
			t.Fatalf("failed to chdir: %v", err)
		}
		defer func() {
			if err := os.Chdir(oldWd); err != nil {
				t.Errorf("failed to restore cwd: %v", err)
			}
		}()

		files, err := GetAllAllowedFilesAndDirsFromPath(homeDir)
		if err != nil {
			t.Fatalf("GetAllAllowedFilesAndDirsFromPath failed: %v", err)
		}

		zipPath, err := CompressFiles(files)
		if err != nil {
			t.Fatalf("CompressFiles failed: %v", err)
		}

		// Archiver preserves directory paths relative to CWD.
		verifyZipContents(t, zipPath, []string{"main.go", "subpkg/helper.go"})
	})

	t.Run("handles empty input", func(t *testing.T) {
		homeDir := t.TempDir()

		t.Setenv("HOME", homeDir)

		zipPath, err := CompressFiles([]string{})
		if err != nil {
			// Error is acceptable for empty input.
			return
		}
		if _, statErr := os.Stat(zipPath); statErr != nil {
			t.Fatalf("zip not created: %v", statErr)
		}
	})
}

func TestGetZipFriendlySize(t *testing.T) {
	t.Parallel()

	t.Run("returns human-readable size for bytes", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "small.zip")
		if err := os.WriteFile(path, []byte("hi"), 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		size, err := GetZipFriendlySize(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if size != "2 B" {
			t.Errorf("expected '2 B', got: %s", size)
		}
	})

	t.Run("returns human-readable size for kilobytes", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "medium.zip")
		content := strings.Repeat("a", 1500)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		size, err := GetZipFriendlySize(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if size == "" {
			t.Fatal("expected non-empty size string")
		}
		if !strings.Contains(size, "kB") {
			t.Errorf("expected size string to contain 'kB', got: %s", size)
		}
	})

	t.Run("returns human-readable size for megabytes", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "large.zip")
		// 2 MB worth of data
		content := strings.Repeat("a", 2000000)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		size, err := GetZipFriendlySize(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if size == "" {
			t.Fatal("expected non-empty size string")
		}
		if !strings.Contains(size, "MB") {
			t.Errorf("expected size string to contain 'MB', got: %s", size)
		}
	})

	t.Run("returns error for non-existent file", func(t *testing.T) {
		t.Parallel()
		_, err := GetZipFriendlySize("/nonexistent/file.zip")
		if err == nil {
			t.Fatal("expected error for non-existent file")
		}
	})
}

func TestDeleteHuskyFile(t *testing.T) {
	t.Parallel()

	t.Run("removes file successfully", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "to-delete.zip")
		if err := os.WriteFile(path, []byte("content"), 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		err := DeleteHuskyFile(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Fatal("file should have been deleted")
		}
	})

	t.Run("returns error for non-existent file", func(t *testing.T) {
		t.Parallel()
		err := DeleteHuskyFile("/nonexistent/file.zip")
		if err == nil {
			t.Fatal("expected error for non-existent file")
		}
	})
}
