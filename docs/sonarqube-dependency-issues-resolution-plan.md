# Resolution Plan: SonarQube External Issues Ignored for Dependency Files

## Problem Statement

When importing WizCLI scan results into SonarQube as external issues, some findings are ignored with messages like:

```
INFO: External issues ignored for 4 unknown files, including: 
  - huskyCI/huskyCI_Placeholder_File
  - pytest:7.4.3 (requirements.txt)
  - fastapi:0.104.1 (requirements.txt)
  - gunicorn:21.2.0 (requirements.txt)
```

**Root cause**: SonarQube's generic issue import requires file paths that match actual files in the analyzed codebase. When HuskyCI reports findings with file paths that don't exist (like `pytest:7.4.3 (requirements.txt)`), SonarQube discards them.

## Research Findings

### Current HuskyCI Implementation

#### 1. WizCLI File Path Generation (`api/securitytest/wizcli.go`)

WizCLI findings use a composite `location` string for the `File` field:

```go
// For library/OS package vulnerabilities:
location := pkg.Name                                   // "pytest"
if pkg.Version != "" {
    location += ":" + pkg.Version                      // "pytest:7.4.3"
}
if pkg.Path != "" {
    location += " (" + strings.TrimLeft(pkg.Path, "/") + ")"  // "pytest:7.4.3 (requirements.txt)"
}
```

This produces strings like:
- `pytest:7.4.3 (requirements.txt)`
- `lodash:4.17.4 (package-lock.json)`
- `huskyCI/huskyCI_Placeholder_File` (for findings without a source file)

#### 2. Other Scanners' Approach

**Safety (Python dependencies)**:
- Hardcodes `File = "requirements.txt"` (line 130 in `safety.go`)
- Works if `requirements.txt` exists in the repo

**NpmAudit (JavaScript dependencies)**:
- Hardcodes `File = "package-lock.json"` (line 196 in `npmaudit.go`)
- Works if `package-lock.json` exists in the repo

#### 3. SonarQube Generic Issue Format

```json
{
  "rules": [{ "id": "rule-id", ... }],
  "issues": [{ 
    "ruleId": "rule-id",
    "primaryLocation": {
      "filePath": "./actual/file/path.py",
      "message": "..."
    }
  }]
}
```

The `filePath` MUST match a file that exists in the SonarQube project analysis.

### Dependency File Types by Ecosystem

| Ecosystem | Lock File | Manifest File |
|-----------|-----------|---------------|
| Python | requirements.txt (can be), Pipfile.lock, poetry.lock | requirements.txt, Pipfile, pyproject.toml |
| JavaScript/Node | package-lock.json, yarn.lock, pnpm-lock.yaml | package.json |
| Java/Maven | pom.xml (acts as both) | pom.xml |
| Java/Gradle | build.gradle, gradle.lockfile | build.gradle |
| Ruby | Gemfile.lock | Gemfile |
| Go | go.sum, go.mod | go.mod |
| PHP | composer.lock | composer.json |
| Rust | Cargo.lock | Cargo.toml |
| .NET | packages.lock.json, *.csproj | *.csproj |
| Docker | Dockerfile, docker-compose.yml | - |
| Infrastructure | *.tf, *.yaml, *.json | - |

### WizCLI Finding Categories

From `wizcli.go`, WizCLI produces findings from:

1. **Libraries** (`result.libraries`) - Direct/transitive dependencies
2. **OS Packages** (`result.osPackages`) - OS-level packages
3. **Secrets** (`result.secrets`) - Hardcoded credentials (has actual file paths)
4. **Data Findings** (`result.dataFindings`) - Sensitive data patterns (has actual file paths)
5. **End of Life Technologies** (`result.endOfLifeTechnologies`) - EOL software (no file path)

**Problem categories**:
- Libraries/OS Packages with `pkg.Path` pointing to a lock file
- End of Life Technologies (no file path at all)
- Findings where WizCLI returns empty `pkg.Path`

## Solution Options

### Option A: Canonical Lock File Path Mapping

**Approach**: Map WizCLI's `pkg.Path` to the actual lock file path in the repository.

**Implementation**:
1. Parse WizCLI's `pkg.Path` (e.g., `/package-lock.json`, `/requirements.txt`)
2. Resolve to relative path: `./package-lock.json`, `./requirements.txt`
3. Include all lock files if multiple exist (e.g., nested `requirements.txt`)

**Pros**:
- Issues appear in SonarQube at the actual lock file location
- Developers see where to fix (in the lock/manifest file)
- Minimal change to existing logic

**Cons**:
- Requires the lock file to exist in the repo
- Multiple lock files create ambiguity (which one caused the issue?)
- Some projects don't commit lock files

**Affected code**: `api/securitytest/wizcli.go` lines 135-163

---

### Option B: Project Root Placeholder File

**Approach**: Create a placeholder file path for dependency findings that don't map to source files.

**Implementation**:
1. Use a standard placeholder like `./DEPENDENCY_SECURITY.md` or `./vulnerabilities.json`
2. This file is auto-created by SonarQube's analysis when it doesn't exist
3. Or, document that users should create this file

**Pros**:
- All issues import successfully
- One place to see all dependency issues
- No ambiguity about which lock file

**Cons**:
- Requires user action (create the placeholder file)
- Not discoverable in actual code location
- SonarQube may not create files that don't exist

---

### Option C: Conditional Issue Generation

**Approach**: Only generate SonarQube issues for findings that have valid file paths. Skip dependency issues entirely for SonarQube (they're still in HuskyCI output).

**Implementation**:
1. In `client/integration/sonarqube/sonarqube.go`, filter out issues with invalid file paths
2. Log a warning summarizing skipped issues
3. Document that dependency issues are best viewed in HuskyCI dashboard

**Pros**:
- Clean SonarQube import (no warnings)
- No false positives about "unknown files"
- HuskyCI remains source of truth for all findings

**Cons**:
- Dependency issues not visible in SonarQube
- Requires context switching to see full picture
- May confuse users expecting all issues in one place

---

### Option D: Hybrid Approach (RECOMMENDED)

**Approach**: Best-effort mapping with fallback.

**Implementation**:

1. **For findings with a valid lock file path** (from WizCLI's `pkg.Path`):
   - Convert `/package-lock.json` → `./package-lock.json`
   - Convert `/requirements.txt` → `./requirements.txt`
   - Convert `/path/to/nested/lock.file` → `./path/to/nested/lock.file`
   
2. **For findings without a file path** (empty `pkg.Path`, EOL technologies):
   - Use the repository's primary manifest file as fallback
   - Detect from common files: `package.json`, `requirements.txt`, `pyproject.toml`, `go.mod`, etc.
   - If no manifest found, use `./SECURITY.md` as placeholder

3. **SonarQube output filtering**:
   - Skip issues where the target file doesn't exist
   - Log summary of skipped issues by category
   - Add metadata to issue description: "Dependency: pytest:7.4.3"

**Pros**:
- Maximum issues imported successfully
- Issues at most relevant location (lock file where possible)
- Graceful degradation when files don't exist
- Clear documentation of what was imported vs skipped

**Cons**:
- Most complex implementation
- Requires manifest detection logic

**Affected code**:
- `api/securitytest/wizcli.go` - modify `collectCVEs` to extract clean file path
- `client/integration/sonarqube/sonarqube.go` - add file path validation and fallback logic

---

## Recommended Implementation: Option D (Hybrid)

### Phase 1: File Path Normalization

Modify `parseWizCLIJSON` in `api/securitytest/wizcli.go`:

```go
collectCVEs := func(pkgs []wizPackageWithVulns) {
    for _, pkg := range pkgs {
        // Extract clean file path from pkg.Path
        filePath := ""
        if pkg.Path != "" {
            // WizCLI returns absolute paths like /package-lock.json
            // Convert to relative: ./package-lock.json
            filePath = "." + strings.TrimSuffix(pkg.Path, "/")
            if !strings.HasPrefix(filePath, "./") {
                filePath = "./" + strings.TrimLeft(filePath, "./")
            }
        }
        
        // Build location string for display (kept in Title/Details)
        location := pkg.Name
        if pkg.Version != "" {
            location += ":" + pkg.Version
        }
        
        line := ""
        if pkg.StartLine > 0 {
            line = strconv.Itoa(pkg.StartLine)
        }
        
        for _, v := range pkg.Vulnerabilities {
            if v.Name == "" {
                continue
            }
            details := v.Name
            if v.FixedVersion != "" {
                details += " (fixed: " + v.FixedVersion + ")"
            }
            if v.Description != "" {
                details += " - " + v.Description
            }
            
            // File is now a clean path, location info in details
            addFinding(v.Name, strings.ToUpper(v.Severity), filePath, line, 
                details + " [Dependency: " + location + "]")
        }
    }
}
```

### Phase 2: Manifest File Detection

Add a helper function to detect the primary manifest file:

```go
// detectManifestFile returns the most appropriate manifest/lock file
// for dependency findings when no specific file is known
func detectManifestFile(wd string) string {
    manifestPriority := []string{
        // JavaScript/Node
        "./package-lock.json",
        "./yarn.lock",
        "./pnpm-lock.yaml",
        "./package.json",
        // Python
        "./requirements.txt",
        "./Pipfile.lock",
        "./poetry.lock",
        "./pyproject.toml",
        // Go
        "./go.sum",
        "./go.mod",
        // Java
        "./pom.xml",
        "./build.gradle",
        // Ruby
        "./Gemfile.lock",
        // Rust
        "./Cargo.lock",
        // PHP
        "./composer.lock",
        // Fallback
        "./SECURITY.md",
    }
    
    for _, f := range manifestPriority {
        if _, err := os.Stat(filepath.Join(wd, f)); err == nil {
            return f
        }
    }
    
    // Ultimate fallback
    return "./DEPENDENCIES.md"
}
```

### Phase 3: SonarQube Output Filtering

In `client/integration/sonarqube/sonarqube.go`:

```go
// isValidFilePath checks if a file path is likely to exist in SonarQube
func isValidFilePath(filePath string) bool {
    if filePath == "" {
        return false
    }
    
    // Reject placeholder patterns
    invalidPatterns := []string{
        "huskyCI_Placeholder_File",
        "UNKNOWN_FILE",
        ":/", // package:version patterns
    }
    
    for _, pattern := range invalidPatterns {
        if strings.Contains(filePath, pattern) {
            return false
        }
    }
    
    // Must look like a file path
    return strings.HasPrefix(filePath, "./") || 
           strings.HasPrefix(filePath, "../") ||
           !strings.Contains(filePath, ":")
}
```

### Phase 4: EOL Technologies Handling

For End of Life technologies (no file path), use manifest detection:

```go
for _, eol := range report.Result.EndOfLifeTechnologies {
    if eol.Name == "" {
        continue
    }
    // Use manifest detection for EOL findings
    filePath := detectManifestFile(".")
    addFinding("End of Life Technology", "MEDIUM", filePath, "", 
        eol.Name + " is end of life [Technology: " + eol.Version + "]")
}
```

## Testing Strategy

### Unit Tests

1. **Test file path normalization**:
   - Input: `/package-lock.json` → Output: `./package-lock.json`
   - Input: `/src/api/requirements.txt` → Output: `./src/api/requirements.txt`
   - Input: `` (empty) → Output: fallback path

2. **Test manifest detection**:
   - Create temp dir with `package-lock.json` → returns that
   - Create temp dir with only `package.json` → returns that
   - Empty temp dir → returns `./SECURITY.md`

3. **Test SonarQube output**:
   - Valid file paths generate issues
   - Invalid file paths are filtered
   - Output JSON is valid SonarQube format

### Integration Tests

1. Run HuskyCI with WizCLI on a sample project
2. Generate SonarQube output
3. Import into SonarQube
4. Verify: no "unknown files" warnings
5. Verify: dependency issues visible at correct location

## Migration Notes

### Backward Compatibility

- Existing HuskyCI clients that parse the `File` field for dependency info will see changed format
- The dependency name/version is preserved in the `Details` field with `[Dependency: name:version]`
- This is a breaking change for any tool parsing `File` expecting `package:version` format

### Documentation Updates

- Update HuskyCI docs to explain SonarQube behavior
- Document the new `[Dependency: ...]` format in Details
- Add troubleshooting guide for "unknown files" warnings

## Decision Matrix

| Criterion | Option A | Option B | Option C | Option D |
|-----------|----------|----------|----------|----------|
| Issues imported | Medium | High | Low | High |
| Implementation complexity | Low | Low | Low | Medium |
| User experience | Good | Fair | Poor | Excellent |
| Maintenance burden | Low | Low | Low | Medium |
| Issues at correct location | Partial | No | N/A | Yes |
| Works without lock files | No | Yes | N/A | Yes |

**Recommendation**: Option D provides the best balance of usability and completeness.

## Next Steps

1. [ ] Review and approve this plan
2. [ ] Implement Phase 1 (file path normalization)
3. [ ] Implement Phase 2 (manifest detection)
4. [ ] Implement Phase 3 (SonarQube filtering)
5. [ ] Add unit tests
6. [ ] Add integration tests
7. [ ] Update documentation
8. [ ] Release and monitor
