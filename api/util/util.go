// Copyright 2019 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package util

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"errors"
	"fmt"

	"github.com/githubanotaai/huskyci-api/api/log"
	"github.com/githubanotaai/huskyci-api/api/types"
	"github.com/labstack/echo"
)

const (
	// CertFile contains the address for the API's TLS certificate.
	CertFile = "api/api-tls-cert.pem"
	// KeyFile contains the address for the API's TLS certificate key file.
	KeyFile = "api/api-tls-key.pem"
)

const logInfoAnalysis = "ANALYSIS"
const logActionReceiveRequest = "ReceiveRequest"

var validRepoURL = regexp.MustCompile(`((git|ssh|http(s)?)|((git@|gitlab@)[\w\.]+))(:(//)?)([\w\.@\:/\-~]+)(\.git)(/)?`)

const MaxScannerOutputBytes = 100 * 1024 * 1024

var ErrScannerOutputTooLarge = errors.New("scanner output exceeds size limit")

func ReadBoundedScannerOutput(reader io.Reader) (string, error) {
	body, err := io.ReadAll(io.LimitReader(reader, MaxScannerOutputBytes+1))
	if err != nil {
		return "", err
	}
	if len(body) > MaxScannerOutputBytes {
		return "", fmt.Errorf("%w: limit %d bytes", ErrScannerOutputTooLarge, MaxScannerOutputBytes)
	}
	return string(body), nil
}

// HandleCmd will extract %GIT_REPO%, %GIT_BRANCH% from cmd and replace it with the proper repository URL.
// Also replaces %WIZ_CLIENT_ID% and %WIZ_CLIENT_SECRET% with values from environment variables.
// The changedFiles parameter replaces %CHANGED_FILES% (use empty string when delta scanning is not active).
func HandleCmd(repositoryURL, repositoryBranch, cmd, changedFiles string) string {
	if repositoryURL != "" && repositoryBranch != "" && cmd != "" {
		replace1 := strings.ReplaceAll(cmd, "%GIT_REPO%", repositoryURL)
		replace2 := strings.ReplaceAll(replace1, "%GIT_BRANCH%", repositoryBranch)
		replace3 := strings.ReplaceAll(replace2, "%WIZ_CLIENT_ID%", os.Getenv("HUSKYCI_API_WIZ_CLIENT_ID"))
		replace4 := strings.ReplaceAll(replace3, "%WIZ_CLIENT_SECRET%", os.Getenv("HUSKYCI_API_WIZ_CLIENT_SECRET"))
		replace5 := strings.ReplaceAll(replace4, "%CHANGED_FILES%", changedFiles)
		return replace5
	}
	return ""
}

// HandleGitURLSubstitution will extract GIT_SSH_URL and GIT_URL_TO_SUBSTITUTE from cmd and replace it with the SSH equivalent.
func HandleGitURLSubstitution(rawString string) string {
	gitSSHURL := os.Getenv("HUSKYCI_API_GIT_SSH_URL")
	gitURLToSubstitute := os.Getenv("HUSKYCI_API_GIT_URL_TO_SUBSTITUTE")

	if gitSSHURL == "" || gitURLToSubstitute == "" {
		gitSSHURL = "nil"
		gitURLToSubstitute = "nil"
	}
	cmdReplaced := strings.ReplaceAll(rawString, "%GIT_SSH_URL%", gitSSHURL)
	cmdReplaced = strings.ReplaceAll(cmdReplaced, "%GIT_URL_TO_SUBSTITUTE%", gitURLToSubstitute)

	return cmdReplaced
}

// normalizeGitSSHPrivateKey expands common AWS Secrets Manager one-liner escapes so PEM uses real newlines.
// Many secrets store PEM as a single line with the two-character sequence \ + n instead of an ASCII LF.
func normalizeGitSSHPrivateKey(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	s = strings.ReplaceAll(s, "\\r\\n", "\n")
	s = strings.ReplaceAll(s, "\\n", "\n")
	s = strings.ReplaceAll(s, "\\r", "\n")
	return s
}

// NormalizeGitSSHPrivateKeyFromEnv applies the same unescaping used by HandlePrivateSSHKey (for tests/diagnostics).
func NormalizeGitSSHPrivateKeyFromEnv(s string) string {
	return normalizeGitSSHPrivateKey(s)
}

// HandlePrivateSSHKey will extract %GIT_PRIVATE_SSH_KEY% from cmd and replace it with the proper private SSH key.
func HandlePrivateSSHKey(rawString string) string {
	privKey := normalizeGitSSHPrivateKey(os.Getenv("HUSKYCI_API_GIT_PRIVATE_SSH_KEY"))
	cmdReplaced := strings.ReplaceAll(rawString, "%GIT_PRIVATE_SSH_KEY%", privKey)
	return cmdReplaced
}

// GetLastLine receives a string with multiple lines and returns it's last
func GetLastLine(s string) string {
	if s == "" {
		return ""
	}
	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(s))
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines[len(lines)-1]
}

// GetAllLinesButLast receives a string with multiple lines and returns all but the last line.
func GetAllLinesButLast(s string) []string {
	if s == "" {
		return []string{}
	}
	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(s))
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	lines = lines[:len(lines)-1]
	return lines
}

// SanitizeSafetyJSON returns a sanitized string from Safety container logs.
// Safety might return a JSON with the "\" and "\"" characters, which needs to be sanitized to be unmarshalled correctly.
func SanitizeSafetyJSON(s string) string {
	if s == "" {
		return ""
	}
	s1 := strings.ReplaceAll(s, "\\", "\\\\")
	s2 := strings.ReplaceAll(s1, "\\\"", "\\\\\"")
	return s2
}

// RemoveDuplicates remove duplicated itens from a slice.
func RemoveDuplicates(s []string) []string {
	mapS := make(map[string]string, len(s))
	i := 0
	for _, v := range s {
		if _, ok := mapS[v]; !ok {
			mapS[v] = v
			s[i] = v
			i++
		}
	}
	return s[:i]
}

// HandleScanError show the right error when json is not expected as output of scan
func HandleScanError(containerOutput string, otherErr error) error {
	return fmt.Errorf("%s\nError from top: %v", boundedScannerOutput(containerOutput), otherErr)
}

func boundedScannerOutput(output string) string {
	const edgeSize = 512
	if len(output) <= edgeSize*2 {
		return output
	}
	prefix := output[:edgeSize]
	suffix := output[len(output)-edgeSize:]
	return fmt.Sprintf("%s\n... scanner output truncated, total bytes: %d ...\n%s", prefix, len(output), suffix)
}

// RedactURL removes URL userinfo before values are written to logs.
func RedactURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		if strings.HasPrefix(raw, "git@") || strings.HasPrefix(raw, "gitlab@") {
			return raw
		}
		if at := strings.LastIndex(raw, "@"); at > 0 {
			return "[redacted]" + raw[at:]
		}
		return "[unparseable]"
	}
	parsed.User = nil
	return parsed.String()
}

// CheckValidInput checks if an user's input is "malicious" or not
func CheckValidInput(repository types.Repository, c echo.Context) (string, error) {

	sanitiziedURL, err := CheckMaliciousRepoURL(repository.URL)
	if err != nil {
		if sanitiziedURL == "" {
			log.Error(logActionReceiveRequest, logInfoAnalysis, 1016, RedactURL(repository.URL))
			reply := map[string]interface{}{"success": false, "error": "invalid repository URL"}
			return "", c.JSON(http.StatusBadRequest, reply)
		}
		log.Error(logActionReceiveRequest, logInfoAnalysis, 1008, "Repository URL regexp ", err)
		reply := map[string]interface{}{"success": false, "error": "internal error"}
		return "", c.JSON(http.StatusInternalServerError, reply)
	}

	if err := CheckMaliciousRepoBranch(repository.Branch, c); err != nil {
		return "", err
	}

	return sanitiziedURL, nil
}

// CheckMaliciousRepoURL verifies if a given URL is a git repository and returns the sanitizied string and its error
func CheckMaliciousRepoURL(repositoryURL string) (string, error) {
	if !validRepoURL.MatchString(repositoryURL) {
		errorMsg := fmt.Sprintf("Invalid URL format: %s", repositoryURL)
		return "", errors.New(errorMsg)
	}
	sanitized := validRepoURL.FindString(repositoryURL)
	if strings.HasPrefix(sanitized, "git@") || strings.HasPrefix(sanitized, "gitlab@") {
		return sanitized, nil
	}

	parsed, err := url.Parse(sanitized)
	if err != nil {
		return "", err
	}
	switch parsed.Scheme {
	case "git", "http", "https", "ssh":
	default:
		return "", fmt.Errorf("invalid repository URL scheme: %s", parsed.Scheme)
	}
	if parsed.User != nil {
		return "", errors.New("repository URL must not contain credentials")
	}
	if isUnsafeRepoHost(parsed.Hostname()) {
		return "", errors.New("repository URL points to a blocked host")
	}
	return sanitized, nil
}

func isUnsafeRepoHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// CheckMaliciousRepoBranch verifies if a given branch is "malicious" or not
func CheckMaliciousRepoBranch(repositoryBranch string, c echo.Context) error {
	regexpBranch := `^[a-zA-Z0-9_\/.\-\+À-ÿ]*$`
	valid, err := regexp.MatchString(regexpBranch, repositoryBranch)
	if err != nil {
		log.Error(logActionReceiveRequest, logInfoAnalysis, 1008, "Repository Branch regexp ", err)
		reply := map[string]interface{}{"success": false, "error": "internal error"}
		return c.JSON(http.StatusInternalServerError, reply)
	}
	if !valid || hasUnsafePathSegment(repositoryBranch) {
		log.Error(logActionReceiveRequest, logInfoAnalysis, 1017, repositoryBranch)
		reply := map[string]interface{}{"success": false, "error": "invalid repository branch"}
		return c.JSON(http.StatusBadRequest, reply)
	}
	return nil
}

// CheckMaliciousChangedFiles verifies that changed file paths don't contain
// shell metacharacters that could be exploited when substituted into scanner
// commands via %CHANGED_FILES%. Accepts only valid file path characters.
// Returns an error if invalid; empty string is valid (non-PR or no changed files).
func CheckMaliciousChangedFiles(changedFiles string) error {
	if changedFiles == "" {
		return nil
	}
	// Allow: alphanumeric, path separators, dots, hyphens, underscores, newlines
	// Block: shell metacharacters ($, `, ;, |, &, <, >, (, ), {, }, !)
	regexpFiles := `^[a-zA-Z0-9_/.\\\n-]*$`
	valid, err := regexp.MatchString(regexpFiles, changedFiles)
	if err != nil {
		return err
	}
	if !valid || hasUnsafeChangedFilePath(changedFiles) {
		return errors.New("invalid changed files: contains forbidden characters")
	}
	return nil
}

func hasUnsafeChangedFilePath(changedFiles string) bool {
	for _, file := range strings.Split(changedFiles, "\n") {
		file = strings.TrimSpace(file)
		if file == "" {
			continue
		}
		if strings.HasPrefix(file, "/") || strings.HasPrefix(file, "\\") || hasUnsafePathSegment(file) {
			return true
		}
	}
	return false
}

func hasUnsafePathSegment(value string) bool {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == '/' || r == '\\'
	})
	for _, part := range parts {
		if part == ".." {
			return true
		}
	}
	return false
}

// CheckMaliciousRID verifies if a given RID is "malicious" or not
func CheckMaliciousRID(RID string, c echo.Context) error {
	regexpRID := `^[-a-zA-Z0-9]*$`
	valid, err := regexp.MatchString(regexpRID, RID)
	if err != nil {
		log.Error("GetAnalysis", logInfoAnalysis, 1008, "RID regexp ", err)
		reply := map[string]interface{}{"success": false, "error": "internal error"}
		return c.JSON(http.StatusInternalServerError, reply)
	}
	if !valid {
		log.Warning("GetAnalysis", logInfoAnalysis, 107, RID)
		reply := map[string]interface{}{"success": false, "error": "invalid RID"}
		return c.JSON(http.StatusBadRequest, reply)
	}
	return nil
}

// AdjustWarningMessage returns the Safety Warning string that will be printed.
func AdjustWarningMessage(warningRaw string) string {
	warning := strings.Split(warningRaw, ":")
	if len(warning) > 1 {
		warning[1] = strings.ReplaceAll(warning[1], "safety_huskyci_analysis_requirements_raw.txt", "'requirements.txt'")
		warning[1] = strings.ReplaceAll(warning[1], " unpinned", "Unpinned")

		return (warning[1] + " huskyCI can check it if you pin it in a format such as this: \"mypacket==3.2.9\" :D")
	}

	return warningRaw
}

// EndOfTheDay returns the the time at the end of the day t.
func EndOfTheDay(t time.Time) time.Time {
	year, month, day := t.Date()
	return time.Date(year, month, day, 23, 59, 59, 0, t.Location())
}

// BeginningOfTheDay returns the the time at the beginning of the day t.
func BeginningOfTheDay(t time.Time) time.Time {
	year, month, day := t.Date()
	return time.Date(year, month, day, 0, 0, 0, 0, t.Location())
}

// CountDigits returns the number of digits in an integer.
func CountDigits(i int) int {
	count := 0
	for i != 0 {
		i /= 10
		count = count + 1
	}

	return count
}

func banditCase(code string, lineNumber int) bool {
	lineNumberLength := CountDigits(lineNumber)
	splitCode := strings.Split(code, "\n")
	for _, codeLine := range splitCode {
		if len(codeLine) > 0 {
			codeLineNumber := codeLine[:lineNumberLength]
			if strings.Contains(codeLine, "#nohusky") && (codeLineNumber == strconv.Itoa(lineNumber)) {
				return true
			}
		}
	}
	return false
}

// VerifyNoHusky verifies if the code string is marked with the #nohusky tag.
func VerifyNoHusky(code string, lineNumber int, securityTool string) bool {
	m := map[string]types.NohuskyFunction{
		"Bandit": banditCase,
	}

	return m[securityTool](code, lineNumber)

}

// SliceContains returns true if a given value is present on the given slice
func SliceContains(slice []string, str string) bool {
	for _, value := range slice {
		if value == str {
			return true
		}
	}
	return false
}

// NormalizeFilePath removes leading "./" prefix from file paths.
// Many security tools (Bandit, Gitleaks, etc.) output paths with "./" prefix,
// but SonarQube expects paths without this prefix.
func NormalizeFilePath(path string) string {
	// Strip container mount prefixes that leak into scan output
	// WizCLI mounts repos at /code, so files appear as "code/Dockerfile" or "/code/Dockerfile"
	path = strings.TrimPrefix(path, "/code/")
	path = strings.TrimPrefix(path, "code/")
	// Bandit/Gosec mount at /go/src/code
	path = strings.TrimPrefix(path, "/go/src/code/")
	return strings.TrimPrefix(path, "./")
}
