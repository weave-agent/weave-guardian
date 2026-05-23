package guardian

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/weave-agent/weave/sdk"
)

const (
	actionFileRead      = "file.read"
	actionFileWrite     = "file.write"
	actionFileDelete    = "file.delete"
	actionFileProtected = "file.write_protected"
	actionPolicyRead    = "policy.read"
	actionPolicyWrite   = "policy.write"
	actionSecretRead    = "secret.read"
	actionCommandExec   = "command.exec_local"
	actionNetworkRead   = "network.read"
	actionUnknown       = "unknown"
)

type classifiedPath struct {
	raw      string
	clean    string
	resolved string
	parts    []string
	base     string
}

func classifyRequest(req sdk.GuardianRequest) string {
	switch req.Action {
	case sdk.GuardianActionRead, sdk.GuardianActionWrite, sdk.GuardianActionDelete:
		return classifyFileAction(req)
	case sdk.GuardianActionExec:
		return actionCommandExec
	case sdk.GuardianActionNetwork:
		return actionNetworkRead
	default:
		return actionUnknown
	}
}

func classifyFileAction(req sdk.GuardianRequest) string {
	path := normalizeRequestPath(req.Path, req.WorkingDir)

	switch req.Action {
	case sdk.GuardianActionRead:
		if isPolicyPath(path) {
			return actionPolicyRead
		}
		if isSensitivePath(path) {
			return actionSecretRead
		}
		return actionFileRead
	case sdk.GuardianActionWrite, sdk.GuardianActionDelete:
		if isPolicyPath(path) {
			return actionPolicyWrite
		}
		if isProtectedPath(path) {
			return actionFileProtected
		}
		if req.Action == sdk.GuardianActionDelete {
			return actionFileDelete
		}
		return actionFileWrite
	default:
		return actionUnknown
	}
}

func normalizeRequestPath(rawPath, workingDir string) classifiedPath {
	if rawPath == "" {
		return classifiedPath{}
	}

	clean := filepath.Clean(rawPath)
	if !filepath.IsAbs(clean) {
		base := workingDir
		if base == "" {
			if wd, err := os.Getwd(); err == nil {
				base = wd
			}
		}
		clean = filepath.Join(base, clean)
	}
	clean = filepath.Clean(clean)

	resolved := resolveSymlinkAware(clean)
	return classifiedPath{
		raw:      rawPath,
		clean:    clean,
		resolved: resolved,
		parts:    splitPathParts(resolved),
		base:     strings.ToLower(filepath.Base(resolved)),
	}
}

func resolveSymlinkAware(path string) string {
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return filepath.Clean(resolved)
	}

	current := path
	missing := []string{}
	for {
		resolved, err = filepath.EvalSymlinks(current)
		if err == nil {
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return filepath.Clean(resolved)
		}

		parent := filepath.Dir(current)
		if parent == current {
			return filepath.Clean(path)
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

func splitPathParts(path string) []string {
	parts := strings.FieldsFunc(filepath.ToSlash(path), func(r rune) bool {
		return r == '/'
	})
	for i := range parts {
		parts[i] = strings.ToLower(parts[i])
	}
	return parts
}

func isSensitivePath(path classifiedPath) bool {
	if path.clean == "" {
		return false
	}

	if slices.Contains(path.parts, ".ssh") || slices.Contains(path.parts, ".gnupg") {
		return true
	}
	if hasPathSuffix(path.parts, ".aws", "credentials") || hasPathSuffix(path.parts, ".config", "gh", "hosts.yml") {
		return true
	}

	base := path.base
	if base == ".env" || strings.HasPrefix(base, ".env.") || base == ".npmrc" || base == ".pypirc" || base == ".netrc" {
		return true
	}
	if strings.HasPrefix(base, "id_") || strings.HasSuffix(base, ".pem") || strings.HasSuffix(base, ".key") {
		return true
	}

	return strings.Contains(base, "token") || strings.Contains(base, "secret") || strings.Contains(base, "credential")
}

func isPolicyPath(path classifiedPath) bool {
	if path.clean == "" {
		return false
	}

	if hasAnyPathSegment(path.parts, "guardian", "sandbox") && isConfigOrPolicyFile(path.base) {
		return true
	}
	if hasPathSuffix(path.parts, ".weave", "settings.json") || hasPathSuffix(path.parts, ".weave", "config.json") {
		return true
	}
	if hasPathSuffix(path.parts, ".weave", "extensions", "guardian") || hasPathSuffix(path.parts, ".weave", "extensions", "sandbox") {
		return true
	}
	if slices.Contains(path.parts, "extensions") && isConfigOrPolicyFile(path.base) {
		return true
	}
	if slices.Contains(path.parts, ".weave") && strings.Contains(path.base, "policy") {
		return true
	}

	return false
}

func isProtectedPath(path classifiedPath) bool {
	if path.clean == "" {
		return false
	}

	if slices.Contains(path.parts, ".git") || slices.Contains(path.parts, ".weave") {
		return true
	}
	if hasPathSuffix(path.parts, ".config", "weave") {
		return true
	}

	if runtime.GOOS == "windows" {
		return false
	}

	protectedRoots := []string{"/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/private/etc", "/sbin", "/system", "/usr"}
	resolved := filepath.ToSlash(strings.ToLower(path.resolved))
	for _, root := range protectedRoots {
		if resolved == root || strings.HasPrefix(resolved, root+"/") {
			return true
		}
	}

	return false
}

func isConfigOrPolicyFile(base string) bool {
	if base == "" {
		return false
	}
	if strings.Contains(base, "policy") || strings.Contains(base, "settings") || strings.Contains(base, "config") {
		return true
	}
	return base == "guardian.json" || base == "guardian.yaml" || base == "guardian.yml" ||
		base == "sandbox.json" || base == "sandbox.yaml" || base == "sandbox.yml"
}

func hasAnyPathSegment(parts []string, segments ...string) bool {
	for _, part := range parts {
		if slices.Contains(segments, part) {
			return true
		}
	}
	return false
}

func hasPathSuffix(parts []string, suffix ...string) bool {
	if len(parts) < len(suffix) {
		return false
	}
	offset := len(parts) - len(suffix)
	for i, want := range suffix {
		if parts[offset+i] != want {
			return false
		}
	}
	return true
}

func containsOrdered(parts []string, sequence ...string) bool {
	if len(sequence) == 0 {
		return true
	}
	next := 0
	for _, part := range parts {
		if part == sequence[next] {
			next++
			if next == len(sequence) {
				return true
			}
		}
	}
	return false
}
