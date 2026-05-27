package guardian

import (
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"mvdan.cc/sh/v3/syntax"
)

const (
	actionCommandExecLocal   = "command.exec_local"
	actionCommandExecRemote  = "command.exec_remote"
	actionCommandObfuscated  = "command.obfuscated"
	actionSecretExfiltrate   = "secret.exfiltrate" //nolint:gosec // Action names mention secrets but are policy taxonomy, not credentials.
	shellUnsupportedSyntaxID = "unsupported shell syntax"
	shellOptionTerminator    = "--"
	commandCurl              = "curl"
	commandWget              = "wget"
)

type shellCommand struct {
	Stages []shellStage
	Issues []string
}

type shellStage struct {
	Tokens    []string
	Operator  string
	Redirects []shellRedirect
}

type shellRedirect struct {
	Operator string
	Target   string
}

type execClassification struct {
	ActionTypes           []string
	StageActionTypes      []string
	CompositionActionType string
}

func classifyExecCommand(command string) string {
	return classifyExecCommandInWorkingDir(command, "")
}

func classifyExecCommandInWorkingDir(command, workingDir string) string {
	actions := classifyExecCommandClassificationInWorkingDir(command, workingDir).ActionTypes
	if len(actions) == 0 {
		return actionCommandExecLocal
	}

	actionType := actionUnknown
	for _, stageAction := range actions {
		if commandActionRank(stageAction) > commandActionRank(actionType) {
			actionType = stageAction
		}
	}
	return actionType
}

func classifyExecCommandClassificationInWorkingDir(command, workingDir string) execClassification {
	parsed := decomposeShellCommand(command)
	if len(parsed.Issues) > 0 {
		return execClassification{
			ActionTypes:      []string{actionCommandObfuscated},
			StageActionTypes: []string{actionCommandObfuscated},
		}
	}

	if len(parsed.Stages) == 0 {
		return execClassification{
			ActionTypes:      []string{actionCommandExecLocal},
			StageActionTypes: []string{actionCommandExecLocal},
		}
	}

	stageActions := make([]string, 0, len(parsed.Stages)+1)
	for _, stage := range parsed.Stages {
		stageActions = append(stageActions, classifyShellStage(stage, workingDir))
	}
	classification := execClassification{
		ActionTypes:      append([]string(nil), stageActions...),
		StageActionTypes: append([]string(nil), stageActions...),
	}
	if compositionAction := detectCompositionAction(parsed.Stages, stageActions, workingDir); compositionAction != "" {
		classification.ActionTypes = append(classification.ActionTypes, compositionAction)
		classification.CompositionActionType = compositionAction
	}

	return classification
}

func classifyShellStage(stage shellStage, workingDir string) string {
	actionType := classifyShellStageBase(stage, workingDir)
	if redirectReadAction, ok := classifyRedirectReads(stage.Redirects, workingDir); ok {
		if actionType == actionNetworkWrite && redirectReadAction == actionSecretRead {
			return actionSecretExfiltrate
		}
		if commandActionRank(redirectReadAction) > commandActionRank(actionType) {
			return redirectReadAction
		}
	}
	if redirectAction, ok := classifyRedirectWrites(stage.Redirects, workingDir); ok && commandActionRank(redirectAction) > commandActionRank(actionType) {
		return redirectAction
	}
	return actionType
}

func classifyShellStageBase(stage shellStage, workingDir string) string { //nolint:gocyclo // Command family classification is intentionally centralized.
	if len(stage.Tokens) == 0 {
		if actionType, ok := classifyRedirectWrites(stage.Redirects, workingDir); ok {
			return actionType
		}
		return actionCommandRead
	}

	tokens := stage.Tokens
	name := normalizedCommandName(tokens[0])
	args := tokens[1:]

	switch name {
	case "git":
		return classifyGitCommand(args)
	case "gh":
		return classifyGitHubCommand(args)
	case "rm", "rmdir", "unlink":
		if isDangerousDelete(args) {
			return actionCommandDangerousDelete
		}
		if actionType, ok := classifyShellPathAction(shellPathArgs(args), actionFileDelete, workingDir); ok {
			return actionType
		}
		return actionFileDelete
	case "mv", "cp", "mkdir", "touch", "tee":
		if actionType, ok := classifyShellPathAction(shellWritePathArgs(name, args), actionCommandWrite, workingDir); ok {
			return actionType
		}
		return actionCommandWrite
	case "sed":
		if hasShortFlag(args, "i") || hasLongFlag(args, "in-place") {
			if actionType, ok := classifyShellPathAction(shellPathArgs(args), actionCommandWrite, workingDir); ok {
				return actionType
			}
			return actionCommandWrite
		}
		return actionCommandRead
	case "find":
		if findDangerousDelete(args) {
			return actionCommandDangerousDelete
		}
		if findMutates(args) {
			return actionCommandWrite
		}
		return actionCommandRead
	case "dd", "truncate", "shred":
		if actionType, ok := classifyShellPathAction(shellWritePathArgs(name, args), actionCommandWrite, workingDir); ok {
			return actionType
		}
		return actionCommandWrite
	case "rsync":
		return classifyRsyncCommand(args, workingDir)
	case "grep", "rg", "cat", "ls", "pwd", "wc", "head", "tail", "stat":
		if stageReadsSensitivePath(name, args, workingDir) {
			return actionSecretRead
		}
		if actionType, ok := classifyRedirectWrites(stage.Redirects, workingDir); ok {
			return actionType
		}
		return actionCommandRead
	case "env", "printenv":
		return classifyEnvironmentRead(args)
	case "security", "op", "pass":
		return classifyCredentialCommand(name, args)
	case "aws", "gcloud", "kubectl":
		return classifyCloudCredentialOrNetworkCommand(name, args)
	case commandCurl, commandWget:
		return classifyNetworkCommand(name, args, workingDir)
	case "nc", "netcat", "socat", "ftp", "sftp", "ssh", "scp":
		return classifyNetworkToolCommand(name, args)
	case "http", "https":
		return classifyHTTPieCommand(args)
	case "npm", "pnpm", "yarn", "bun":
		return classifyJavaScriptPackageCommand(name, args)
	case "go":
		return classifyGoCommand(args)
	case "cargo":
		return classifyCargoCommand(args)
	case "python", "python3", "py":
		return classifyPythonCommand(args)
	case "node", "deno":
		return classifyNodeCommand(args)
	case "perl", "ruby", "php":
		return classifyInterpreterCommand(args)
	case "uv":
		return classifyUVCommand(args)
	case "pip", "pip3":
		return classifyPipCommand(args)
	case "make", "just":
		return classifyTaskRunnerCommand(args)
	case "kill", "pkill", "killall":
		return actionSystemSignal
	case "systemctl", "service", "launchctl":
		return actionSystemService
	case "source", ".":
		return classifySourceCommand(args, workingDir)
	case "get", "options":
		return actionNetworkRead
	case "post", "put", "patch", "delete":
		return actionNetworkWrite
	default:
		if actionType, ok := classifyRedirectWrites(stage.Redirects, workingDir); ok {
			return actionType
		}
		return actionCommandExecLocal
	}
}

const actionCommandDangerousDelete = "command.dangerous_delete"

func commandActionRank(actionType string) int {
	switch actionType {
	case actionCommandExecRemote, actionCommandObfuscated, actionCommandDangerousDelete, actionFileProtected, actionPolicyWrite, actionGitHistoryRewrite, actionSecretExfiltrate:
		return 100
	case actionGitRemoteWrite, actionNetworkWrite:
		return 90
	case actionGitDiscard:
		return 80
	case actionFileDelete, actionGitWrite, actionCommandWrite:
		return 70
	case actionPackageGlobal, actionSystemService:
		return 68
	case actionPackageInstall, actionPackageScript, actionSystemSignal:
		return 65
	case actionCommandExecLocal:
		return 60
	case actionNetworkRead:
		return 50
	case actionSecretRead:
		return 45
	case actionGitRead, actionCommandRead, actionPackageBuild, actionPackageTest:
		return 40
	default:
		return 10
	}
}

func detectCompositionAction(stages []shellStage, actions []string, workingDir string) string {
	secretTainted := false
	networkTainted := false
	downloadedPaths := map[string]struct{}{}
	for i := range len(stages) - 1 {
		stageDownloadsNetworkRead(stages[i], actions[i], workingDir, downloadedPaths)
		if stageExecutesDownloadedPath(stages[i+1], workingDir, downloadedPaths) {
			return actionCommandExecRemote
		}
		if stages[i].Operator != "|" {
			secretTainted = false
			networkTainted = false
			continue
		}
		secretTainted = secretTainted || actions[i] == actionSecretRead
		networkTainted = networkTainted || actions[i] == actionNetworkRead
		if networkTainted && isExecutionSink(stages[i+1]) {
			return actionCommandExecRemote
		}
		if secretTainted && actions[i+1] == actionNetworkWrite {
			return actionSecretExfiltrate
		}
		if isDecodeStage(stages[i]) {
			return actionCommandObfuscated
		}
	}
	return ""
}

func stageDownloadsNetworkRead(stage shellStage, action, workingDir string, downloadedPaths map[string]struct{}) bool {
	if len(stage.Tokens) == 0 || action != actionCommandWrite {
		return false
	}
	name := normalizedCommandName(stage.Tokens[0])
	if name != commandCurl && name != commandWget {
		return false
	}
	args := stage.Tokens[1:]
	if classifyNetworkRequestAction(name, args, workingDir) != actionNetworkRead {
		return false
	}
	for i := range args {
		output, ok := networkOutputTarget(name, strings.ToLower(args[i]), args, i)
		if !ok || output == "" || isStdoutTarget(output) {
			continue
		}
		downloadedPaths[normalizeShellPathForMatch(output, workingDir)] = struct{}{}
		return true
	}
	return false
}

func stageExecutesDownloadedPath(stage shellStage, workingDir string, downloadedPaths map[string]struct{}) bool {
	if len(downloadedPaths) == 0 || len(stage.Tokens) == 0 {
		return false
	}
	if isExecutionSink(stage) {
		for _, arg := range stage.Tokens[1:] {
			if _, ok := downloadedPaths[normalizeShellPathForMatch(arg, workingDir)]; ok {
				return true
			}
		}
	}
	_, ok := downloadedPaths[normalizeShellPathForMatch(stage.Tokens[0], workingDir)]
	return ok
}

func normalizeShellPathForMatch(path, workingDir string) string {
	if workingDir != "" && !filepath.IsAbs(path) {
		path = filepath.Join(workingDir, path)
	}
	return filepath.Clean(path)
}

func isExecutionSink(stage shellStage) bool {
	if len(stage.Tokens) == 0 {
		return false
	}
	switch normalizedCommandName(stage.Tokens[0]) {
	case "bash", "sh", "zsh", "fish", "python", "python3", "py", "perl", "ruby", "node", "deno", "php", "source", ".":
		return true
	default:
		return false
	}
}

func isDecodeStage(stage shellStage) bool {
	if len(stage.Tokens) == 0 {
		return false
	}
	name := normalizedCommandName(stage.Tokens[0])
	switch name {
	case "base64", "xxd", "openssl", "certutil":
		return hasAnyArg(stage.Tokens[1:], "-d", "--decode", "-decode", "enc") || hasShortFlag(stage.Tokens[1:], "d")
	default:
		return false
	}
}

func stageReadsSensitivePath(command string, args []string, workingDir string) bool {
	switch command {
	case "cat", "head", "tail", "stat", "wc":
		for _, arg := range args {
			if isShellFileArg(arg) && isSensitiveShellPath(arg, workingDir) {
				return true
			}
		}
	case "grep", "rg":
		if len(args) == 0 {
			return false
		}
		for _, arg := range args[1:] {
			if isShellFileArg(arg) && isSensitiveShellPath(arg, workingDir) {
				return true
			}
		}
	}
	return false
}

func isShellFileArg(arg string) bool {
	if arg == "" || strings.HasPrefix(arg, "-") {
		return false
	}
	return !strings.Contains(arg, "://")
}

func classifyGitCommand(args []string) string { //nolint:gocyclo // Git subcommands map to one taxonomy in a single switch.
	if len(args) == 0 {
		return actionGitRead
	}

	subcommand := strings.ToLower(args[0])
	subArgs := args[1:]
	switch subcommand {
	case "status", "diff", "log", "show", "grep", "ls-files", "rev-parse", "remote", "blame", "describe":
		return actionGitRead
	case "config":
		if gitConfigWrites(subArgs) {
			return actionGitWrite
		}
		return actionGitRead
	case "branch":
		if hasAnyArg(subArgs, "-d", "-D", "--delete", "-m", "-M", "--move", "-c", "-C", "--copy") {
			return actionGitWrite
		}
		return actionGitRead
	case "add", "commit", "merge", "cherry-pick", "revert", "tag", "stash", "switch", "checkout":
		if subcommand == "commit" && hasLongFlag(subArgs, "amend") {
			return actionGitHistoryRewrite
		}
		if subcommand == "checkout" && hasCheckoutPathspec(subArgs) {
			return actionGitDiscard
		}
		if subcommand == "stash" && hasAnyArg(subArgs, "drop", "clear", "pop") {
			return actionGitDiscard
		}
		return actionGitWrite
	case "restore":
		return actionGitDiscard
	case "clean":
		if hasShortFlag(subArgs, "x") && (hasShortFlag(subArgs, "f") || hasLongFlag(subArgs, "force")) {
			return actionCommandDangerousDelete
		}
		return actionGitDiscard
	case "reset":
		if hasAnyArg(subArgs, "--hard", "--merge", "--keep") {
			return actionGitDiscard
		}
		return actionGitHistoryRewrite
	case "rebase", "filter-branch", "replace":
		return actionGitHistoryRewrite
	case "push":
		return actionGitRemoteWrite
	case "pull":
		return actionGitWrite
	case "fetch", "clone":
		return actionGitRead
	default:
		return actionGitWrite
	}
}

func classifyGitHubCommand(args []string) string {
	if len(args) == 0 {
		return actionCommandExecLocal
	}
	command := strings.ToLower(args[0])
	rest := args[1:]
	switch command {
	case "auth":
		if len(rest) > 0 && strings.EqualFold(rest[0], "token") {
			return actionSecretRead
		}
		return actionCommandRead
	case "api":
		for i, arg := range rest {
			lower := strings.ToLower(arg)
			if lower == "-x" || lower == "--method" {
				if i+1 < len(rest) && isWriteHTTPMethod(rest[i+1]) {
					return actionNetworkWrite
				}
			}
			if strings.HasPrefix(lower, "-x") && len(arg) > 2 && isWriteHTTPMethod(arg[2:]) {
				return actionNetworkWrite
			}
			if strings.HasPrefix(lower, "--method=") && isWriteHTTPMethod(arg[len("--method="):]) {
				return actionNetworkWrite
			}
			if isNetworkBodyFlag(lower) {
				return actionNetworkWrite
			}
		}
		return actionNetworkRead
	default:
		return actionCommandExecLocal
	}
}

func gitConfigWrites(args []string) bool {
	for _, arg := range args {
		switch arg {
		case "--get", "--get-all", "--list", "-l", "--show-origin", "--show-scope", "--name-only":
			return false
		case "--unset", "--unset-all", "--rename-section", "--remove-section", "--add", "--replace-all":
			return true
		}
	}
	return len(args) >= 2 && !strings.HasPrefix(args[0], "-")
}

func hasCheckoutPathspec(args []string) bool {
	for i, arg := range args {
		if arg == shellOptionTerminator && i+1 < len(args) {
			return true
		}
	}
	if len(args) == 1 && isLikelyPathspec(args[0]) {
		return true
	}
	if len(args) > 1 && args[0] != "-b" && args[0] != "-B" && args[0] != "--branch" {
		return slices.ContainsFunc(args, isLikelyPathspec)
	}
	return false
}

func classifyNetworkCommand(name string, args []string, workingDir string) string {
	requestAction := classifyNetworkRequestAction(name, args, workingDir)
	if requestAction == actionSecretExfiltrate {
		return requestAction
	}
	if outputAction, ok := classifyNetworkOutputWrite(name, args, workingDir); ok {
		if commandActionRank(outputAction) > commandActionRank(requestAction) {
			return outputAction
		}
		return requestAction
	}
	return requestAction
}

func classifyNetworkRequestAction(name string, args []string, workingDir string) string { //nolint:gocyclo // HTTP clients expose several equivalent write indicators.
	if networkUploadReferencesSensitivePath(name, args, workingDir) {
		return actionSecretExfiltrate
	}
	if name == commandWget && (hasLongFlag(args, "post-data") || hasLongFlag(args, "post-file") || hasLongFlag(args, "body-data") || hasLongFlag(args, "body-file")) {
		return actionNetworkWrite
	}
	if name == commandCurl && hasCurlUploadFile(args) {
		return actionNetworkWrite
	}
	for i, arg := range args {
		lower := strings.ToLower(arg)
		if lower == "-x" || lower == "--request" || lower == "--method" || lower == "--http-method" {
			if i+1 < len(args) && isWriteHTTPMethod(args[i+1]) {
				return actionNetworkWrite
			}
		}
		if strings.HasPrefix(lower, "-x") && len(arg) > 2 && isWriteHTTPMethod(arg[2:]) {
			return actionNetworkWrite
		}
		if strings.HasPrefix(lower, "--request=") && isWriteHTTPMethod(arg[len("--request="):]) {
			return actionNetworkWrite
		}
		if strings.HasPrefix(lower, "--method=") && isWriteHTTPMethod(arg[len("--method="):]) {
			return actionNetworkWrite
		}
		if isNetworkBodyFlag(lower) {
			return actionNetworkWrite
		}
	}
	return actionNetworkRead
}

func classifyHTTPieCommand(args []string) string {
	for _, arg := range args {
		if isReadHTTPMethod(arg) {
			return actionNetworkRead
		}
		if isWriteHTTPMethod(arg) {
			return actionNetworkWrite
		}
	}
	return actionNetworkRead
}

func classifyJavaScriptPackageCommand(name string, args []string) string {
	if len(args) == 0 {
		return actionPackageScript
	}

	command, rest := firstNonFlagArg(args)
	if command == "" {
		return actionPackageScript
	}
	command = strings.ToLower(command)

	if name == "yarn" && command == "global" {
		return actionPackageGlobal
	}
	if hasGlobalPackageFlag(args) {
		return actionPackageGlobal
	}

	switch command {
	case "install", "i", "ci", "add":
		return actionPackageInstall
	case "test", "t", "lint", "check":
		return actionPackageTest
	case "build", "compile":
		return actionPackageBuild
	case "run", "run-script":
		return classifyPackageScript(rest)
	case "exec", "x", "dlx", "create", "init":
		return actionPackageScript
	default:
		if isTestScript(command) {
			return actionPackageTest
		}
		if isBuildScript(command) {
			return actionPackageBuild
		}
		return actionPackageScript
	}
}

func classifyGoCommand(args []string) string {
	if len(args) == 0 {
		return actionPackageScript
	}
	subcommand := strings.ToLower(args[0])
	switch subcommand {
	case "test", "vet":
		return actionPackageTest
	case "build", "generate", "fmt", "fmt ./...", "tool":
		return actionPackageBuild
	case "install":
		return actionPackageGlobal
	case "get", "mod", "work":
		return actionPackageInstall
	case "run":
		return actionPackageScript
	case "env", "version", "list", "doc":
		return actionCommandRead
	default:
		return actionPackageScript
	}
}

func classifyCargoCommand(args []string) string {
	if len(args) == 0 {
		return actionPackageScript
	}
	subcommand := strings.ToLower(args[0])
	switch subcommand {
	case "test", "nextest", "clippy", "check", "bench":
		return actionPackageTest
	case "build", "doc", "fmt":
		return actionPackageBuild
	case "install":
		return actionPackageGlobal
	case "add", "update", "fetch":
		return actionPackageInstall
	case "run":
		return actionPackageScript
	case "metadata", "version", "tree":
		return actionCommandRead
	default:
		return actionPackageScript
	}
}

func classifyPythonCommand(args []string) string {
	if interpreterInlineCode(args) {
		return actionPackageScript
	}
	module, moduleArgs, ok := pythonModule(args)
	if !ok {
		return actionPackageScript
	}
	switch module {
	case "pip":
		return classifyPipCommand(moduleArgs)
	case "pytest", "unittest", "mypy", "ruff":
		return actionPackageTest
	case "build", "compileall":
		return actionPackageBuild
	default:
		return actionPackageScript
	}
}

func classifyNodeCommand(args []string) string {
	if interpreterInlineCode(args) {
		return actionPackageScript
	}
	return actionPackageScript
}

func classifyInterpreterCommand(args []string) string {
	if interpreterInlineCode(args) {
		return actionPackageScript
	}
	return actionPackageScript
}

func interpreterInlineCode(args []string) bool {
	return hasAnyArg(args, "-c", "-e") || hasShortFlag(args, "c") || hasShortFlag(args, "e")
}

func classifyEnvironmentRead(args []string) string {
	if len(args) == 0 {
		return actionSecretRead
	}
	for _, arg := range args {
		upper := strings.ToUpper(arg)
		if strings.Contains(upper, "TOKEN") || strings.Contains(upper, "SECRET") ||
			strings.Contains(upper, "PASSWORD") || strings.Contains(upper, "KEY") ||
			strings.Contains(upper, "CREDENTIAL") {
			return actionSecretRead
		}
	}
	return actionCommandRead
}

func classifyCredentialCommand(name string, args []string) string {
	switch name {
	case "security":
		if len(args) > 0 && strings.HasPrefix(strings.ToLower(args[0]), "find-") {
			return actionSecretRead
		}
	case "op", "pass":
		return actionSecretRead
	}
	return actionCommandExecLocal
}

func classifyCloudCredentialOrNetworkCommand(name string, args []string) string {
	lowerArgs := make([]string, len(args))
	for i, arg := range args {
		lowerArgs[i] = strings.ToLower(arg)
	}
	switch name {
	case "aws":
		return classifyAWSCommand(args, lowerArgs)
	case "gcloud":
		return classifyGCloudCommand(args, lowerArgs)
	case "kubectl":
		if len(lowerArgs) >= 3 && lowerArgs[0] == "config" && lowerArgs[1] == "view" && slices.Contains(lowerArgs, "--raw") {
			return actionSecretRead
		}
	}
	return actionCommandExecLocal
}

func classifyAWSCommand(args, lowerArgs []string) string {
	if len(lowerArgs) >= 3 && lowerArgs[0] == "configure" && lowerArgs[1] == "get" {
		return actionSecretRead
	}
	if len(lowerArgs) >= 2 && lowerArgs[0] == "s3" && slices.Contains([]string{"cp", "mv", "sync"}, lowerArgs[1]) {
		if cloudCopyWritesRemote(args[2:]) {
			return actionNetworkWrite
		}
		return actionNetworkRead
	}
	return actionCommandExecLocal
}

func classifyGCloudCommand(args, lowerArgs []string) string {
	if slices.Contains(lowerArgs, "auth") || slices.Contains(lowerArgs, "credentials") {
		return actionSecretRead
	}
	if len(lowerArgs) >= 3 && lowerArgs[0] == "storage" && slices.Contains([]string{"cp", "rsync"}, lowerArgs[1]) {
		if cloudCopyWritesRemote(args[2:]) {
			return actionNetworkWrite
		}
		return actionNetworkRead
	}
	return actionCommandExecLocal
}

func cloudCopyWritesRemote(args []string) bool {
	paths := shellPathArgs(args)
	if len(paths) == 0 {
		return false
	}
	dst := paths[len(paths)-1]
	return strings.Contains(dst, "://") || strings.HasPrefix(dst, "s3://") || strings.HasPrefix(dst, "gs://")
}

func classifyNetworkToolCommand(name string, args []string) string {
	switch name {
	case "ssh", "sftp":
		return actionNetworkWrite
	case "scp":
		if len(shellPathArgs(args)) >= 2 {
			return actionNetworkWrite
		}
		return actionNetworkRead
	default:
		return actionNetworkWrite
	}
}

func classifyRsyncCommand(args []string, workingDir string) string {
	if hasLongFlag(args, "delete") {
		return actionCommandDangerousDelete
	}
	if actionType, ok := classifyShellPathAction(shellWritePathArgs("rsync", args), actionCommandWrite, workingDir); ok && actionType != actionCommandWrite {
		return actionType
	}
	for _, arg := range shellPathArgs(args) {
		if strings.Contains(arg, ":") && !strings.HasPrefix(arg, "./") && !strings.HasPrefix(arg, "../") {
			return actionNetworkWrite
		}
	}
	return actionCommandWrite
}

func classifySourceCommand(args []string, workingDir string) string {
	if len(args) == 0 {
		return actionCommandExecLocal
	}
	if isSensitiveShellPath(args[0], workingDir) {
		return actionSecretRead
	}
	return actionCommandExecLocal
}

func classifyUVCommand(args []string) string {
	if len(args) == 0 {
		return actionPackageScript
	}
	subcommand := strings.ToLower(args[0])
	switch subcommand {
	case "pip":
		return classifyPipCommand(args[1:])
	case "sync", "add", "remove", "lock":
		return actionPackageInstall
	case "run":
		return classifyPackageScript(args[1:])
	case "tool":
		if len(args) > 1 && strings.EqualFold(args[1], "install") {
			return actionPackageGlobal
		}
		return actionPackageScript
	case "build":
		return actionPackageBuild
	default:
		return actionPackageScript
	}
}

func classifyPipCommand(args []string) string {
	if len(args) == 0 {
		return actionPackageScript
	}
	command, _ := firstNonFlagArg(args)
	switch strings.ToLower(command) {
	case "install":
		if hasGlobalPackageFlag(args) || pipInstallTargetsGlobal(args) {
			return actionPackageGlobal
		}
		return actionPackageInstall
	case "download", "wheel":
		return actionPackageInstall
	case "list", "show", "freeze", "check":
		return actionCommandRead
	default:
		return actionPackageScript
	}
}

func classifyTaskRunnerCommand(args []string) string {
	if len(args) == 0 {
		return actionPackageScript
	}
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return classifyPackageScript([]string{arg})
	}
	return actionPackageScript
}

func classifyPackageScript(args []string) string {
	command, _ := firstNonFlagArg(args)
	command = strings.ToLower(command)
	if isTestScript(command) {
		return actionPackageTest
	}
	if isBuildScript(command) {
		return actionPackageBuild
	}
	return actionPackageScript
}

func firstNonFlagArg(args []string) (string, []string) {
	for i, arg := range args {
		if arg == shellOptionTerminator {
			if i+1 < len(args) {
				return args[i+1], args[i+2:]
			}
			return "", nil
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return arg, args[i+1:]
	}
	return "", nil
}

func hasGlobalPackageFlag(args []string) bool {
	return hasAnyArg(args, "-g", "--global", "--location=global") || hasShortFlag(args, "g") || hasLongFlag(args, "global")
}

func pipInstallTargetsGlobal(args []string) bool {
	return hasAnyArg(args, "--user", "--break-system-packages") || hasLongFlag(args, "user") || hasLongFlag(args, "break-system-packages")
}

func pythonModule(args []string) (string, []string, bool) {
	for i := range args {
		arg := args[i]
		if arg == "-m" {
			if i+1 < len(args) {
				return strings.ToLower(args[i+1]), args[i+2:], true
			}
			return "", nil, false
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return "", nil, false
	}
	return "", nil, false
}

func isTestScript(script string) bool {
	switch script {
	case "test", "tests", "lint", "check", "ci", "verify", "vet", "clippy", "pytest", "mypy", "ruff":
		return true
	default:
		return strings.HasPrefix(script, "test:") || strings.HasPrefix(script, "lint:")
	}
}

func isBuildScript(script string) bool {
	switch script {
	case "build", "compile", "dist", "bundle", "package", "release":
		return true
	default:
		return strings.HasPrefix(script, "build:")
	}
}

func classifyRedirectWrites(redirects []shellRedirect, workingDir string) (string, bool) {
	for _, redirect := range redirects {
		if !strings.Contains(redirect.Operator, ">") {
			continue
		}
		if redirect.Target == "" || isDiscardTarget(redirect.Target) {
			continue
		}
		if actionType := classifyShellWritePath(redirect.Target, actionCommandWrite, workingDir); actionType != actionCommandWrite {
			return actionType, true
		}
		return actionCommandWrite, true
	}
	return "", false
}

func classifyRedirectReads(redirects []shellRedirect, workingDir string) (string, bool) {
	for _, redirect := range redirects {
		if !strings.Contains(redirect.Operator, "<") || redirect.Operator == "<>" || redirect.Target == "" {
			continue
		}
		if isSensitiveShellPath(redirect.Target, workingDir) {
			return actionSecretRead, true
		}
		return actionCommandRead, true
	}
	return "", false
}

func classifyShellPathAction(args []string, fallback, workingDir string) (string, bool) {
	found := false
	for _, arg := range args {
		if !isShellFileArg(arg) {
			continue
		}
		found = true
		if actionType := classifyShellWritePath(arg, fallback, workingDir); actionType != fallback {
			return actionType, true
		}
	}
	return fallback, found
}

func classifyShellWritePath(arg, fallback, workingDir string) string {
	baseDir := workingDir
	if baseDir == "" && !strings.HasPrefix(arg, "/") {
		baseDir = "/"
	}
	path := normalizeRequestPath(arg, baseDir)
	if isPolicyPath(path) {
		return actionPolicyWrite
	}
	if isProtectedPath(path) {
		return actionFileProtected
	}
	return fallback
}

func shellPathArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for i := range args {
		arg := args[i]
		if arg == shellOptionTerminator {
			out = append(out, args[i+1:]...)
			break
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		out = append(out, arg)
	}
	return out
}

func shellWritePathArgs(command string, args []string) []string {
	paths := shellPathArgs(args)
	switch command {
	case "cp", "mv":
		if len(paths) == 0 {
			return nil
		}
		return paths[len(paths)-1:]
	case "dd":
		for _, arg := range args {
			if outputPath, ok := strings.CutPrefix(arg, "of="); ok {
				return []string{outputPath}
			}
		}
		return nil
	default:
		return paths
	}
}

func classifyNetworkOutputWrite(name string, args []string, workingDir string) (string, bool) {
	for i := range args {
		arg := args[i]
		lower := strings.ToLower(arg)
		if output, ok := networkOutputTarget(name, lower, args, i); ok {
			if isStdoutTarget(output) || isDiscardTarget(output) {
				return actionNetworkRead, true
			}
			if output == "" {
				return actionCommandWrite, true
			}
			return classifyShellWritePath(output, actionCommandWrite, workingDir), true
		}
	}
	return "", false
}

func isStdoutTarget(target string) bool {
	switch target {
	case "-", "/dev/stdout", "/proc/self/fd/1", "/dev/fd/1":
		return true
	default:
		return false
	}
}

func isDiscardTarget(target string) bool {
	return target == "/dev/null" || strings.EqualFold(target, "nul")
}

func networkOutputTarget(name, arg string, args []string, index int) (string, bool) {
	switch {
	case arg == "-o" || arg == "--output" || (name == commandWget && arg == "-O"):
		if index+1 < len(args) {
			return args[index+1], true
		}
		return "", true
	case strings.HasPrefix(arg, "--output="):
		return args[index][len("--output="):], true
	case name == commandCurl && strings.HasPrefix(arg, "-o") && len(arg) > 2:
		return args[index][2:], true
	case name == commandWget && strings.HasPrefix(arg, "-O") && len(arg) > 2:
		return args[index][2:], true
	case name == commandCurl && (arg == "-O" || arg == "--remote-name" || arg == "--remote-header-name"):
		return "", true
	default:
		return "", false
	}
}

func isLikelyPathspec(arg string) bool {
	if arg == "" || strings.HasPrefix(arg, "-") {
		return false
	}
	return arg == "." || arg == ".." || strings.HasPrefix(arg, "./") || strings.HasPrefix(arg, "../") ||
		strings.Contains(arg, "/") || strings.Contains(arg, ".") || strings.ContainsAny(arg, "*?[")
}

func findMutates(args []string) bool {
	for _, arg := range args {
		switch arg {
		case "-delete", "-exec", "-execdir":
			return true
		case "-ok", "-okdir":
			return true
		}
	}
	return false
}

func findDangerousDelete(args []string) bool {
	for i, arg := range args {
		if arg == "-delete" {
			return true
		}
		if (arg == "-exec" || arg == "-execdir") && i+1 < len(args) {
			name := normalizedCommandName(args[i+1])
			if name == "rm" || name == "rmdir" || name == "unlink" {
				return true
			}
		}
	}
	return false
}

func isDangerousDelete(args []string) bool {
	recursive := false
	for _, arg := range args {
		if hasShortFlag([]string{arg}, "r") || hasLongFlag([]string{arg}, "recursive") {
			recursive = true
			break
		}
	}
	for _, arg := range args {
		clean := arg
		if clean != "/" {
			clean = strings.TrimRight(clean, "/")
		}
		if clean == "" || strings.HasPrefix(clean, "-") {
			continue
		}
		switch clean {
		case "/", "*", "/*", "./*", "./**", "~", "~/", "~/*", "~/**",
			"$HOME", "${HOME}", "$HOME/*", "${HOME}/*", "$HOME/**", "${HOME}/**",
			"$PWD", "${PWD}", "$PWD/*", "${PWD}/*", "$PWD/**", "${PWD}/**", ".":
			return recursive || clean == "/" || clean == "/*"
		}
	}
	return false
}

func hasShortFlag(args []string, flag string) bool {
	for _, arg := range args {
		if strings.HasPrefix(arg, "--") || !strings.HasPrefix(arg, "-") {
			continue
		}
		if strings.Contains(arg[1:], flag) {
			return true
		}
	}
	return false
}

func hasLongFlag(args []string, flag string) bool {
	prefix := "--" + flag
	for _, arg := range args {
		if arg == prefix || strings.HasPrefix(arg, prefix+"=") {
			return true
		}
	}
	return false
}

func hasAnyArg(args []string, wants ...string) bool {
	for _, arg := range args {
		if slices.Contains(wants, arg) {
			return true
		}
	}
	return false
}

func isNetworkBodyFlag(arg string) bool {
	if arg == "-d" || arg == "--data" || arg == "--data-raw" || arg == "--data-binary" || arg == "--form" || arg == "-f" {
		return true
	}
	return strings.HasPrefix(arg, "--data=") || strings.HasPrefix(arg, "--data-raw=") ||
		strings.HasPrefix(arg, "--data-binary=") || strings.HasPrefix(arg, "--form=")
}

func hasCurlUploadFile(args []string) bool {
	for i := range args {
		lower := strings.ToLower(args[i])
		if lower == "-t" || lower == "--upload-file" {
			return true
		}
		if strings.HasPrefix(lower, "--upload-file=") || (strings.HasPrefix(lower, "-t") && len(args[i]) > 2) {
			return true
		}
	}
	return false
}

func networkUploadReferencesSensitivePath(name string, args []string, workingDir string) bool {
	for i := range args {
		arg := args[i]
		lower := strings.ToLower(arg)
		if sensitiveNetworkUploadValue(networkFlagValue(lower, arg, args, i), workingDir) {
			return true
		}
		if name == commandCurl {
			if uploadFile, ok := curlUploadFileValue(lower, arg, args, i); ok && isSensitiveShellPath(uploadFile, workingDir) {
				return true
			}
		}
		if name == commandWget && strings.HasPrefix(lower, "--post-file=") && isSensitiveShellPath(arg[len("--post-file="):], workingDir) {
			return true
		}
		if name == commandWget && lower == "--post-file" && i+1 < len(args) && isSensitiveShellPath(args[i+1], workingDir) {
			return true
		}
	}
	return false
}

func curlUploadFileValue(lower, original string, args []string, index int) (string, bool) {
	switch {
	case lower == "-t" || lower == "--upload-file":
		if index+1 < len(args) {
			return args[index+1], true
		}
		return "", true
	case strings.HasPrefix(lower, "--upload-file="):
		return original[len("--upload-file="):], true
	case strings.HasPrefix(lower, "-t") && len(original) > 2:
		return original[2:], true
	default:
		return "", false
	}
}

func networkFlagValue(lower, original string, args []string, index int) string {
	for _, prefix := range []string{"--data=", "--data-raw=", "--data-binary=", "--form="} {
		if strings.HasPrefix(lower, prefix) {
			return original[len(prefix):]
		}
	}
	if lower == "-d" || lower == "--data" || lower == "--data-raw" || lower == "--data-binary" || lower == "--form" || lower == "-f" {
		if index+1 < len(args) {
			return args[index+1]
		}
		return ""
	}
	if strings.HasPrefix(lower, "-d") && len(original) > 2 {
		return original[2:]
	}
	if strings.HasPrefix(lower, "-f") && len(original) > 2 {
		return original[2:]
	}
	return ""
}

func sensitiveNetworkUploadValue(value, workingDir string) bool {
	if value == "" {
		return false
	}
	if strings.HasPrefix(value, "@") {
		return isSensitiveShellPath(value[1:], workingDir)
	}
	if _, path, ok := strings.Cut(value, "=@"); ok {
		return isSensitiveShellPath(path, workingDir)
	}
	return false
}

func isSensitiveShellPath(raw, workingDir string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "-") {
		return false
	}
	baseDir := workingDir
	if baseDir == "" && !strings.HasPrefix(raw, "/") {
		baseDir = "/"
	}
	path := normalizeRequestPath(raw, baseDir)
	return isSensitivePath(path)
}

func isReadHTTPMethod(method string) bool {
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "OPTIONS":
		return true
	default:
		return false
	}
}

func isWriteHTTPMethod(method string) bool {
	switch strings.ToUpper(method) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

func decomposeShellCommand(command string) shellCommand {
	parsed := shellCommand{}
	parsed.Issues = append(parsed.Issues, shellASTIssues(command)...)
	tokens, issues := tokenizeShell(command)
	parsed.Issues = append(parsed.Issues, issues...)
	if len(tokens) == 0 {
		return parsed
	}

	stages, issues := splitShellStages(tokens)
	parsed.Issues = append(parsed.Issues, issues...)
	for _, stage := range stages {
		unwrapped, issues := unwrapShellStage(stage)
		parsed.Issues = append(parsed.Issues, issues...)
		parsed.Stages = append(parsed.Stages, unwrapped...)
	}

	return parsed
}

func shellASTIssues(command string) []string {
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return []string{shellUnsupportedSyntaxID + ": " + err.Error()}
	}

	var issues []string
	syntax.Walk(file, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.CmdSubst:
			if !isSafeCommandSubstitution(n) {
				issues = append(issues, shellUnsupportedSyntaxID+": command substitution")
			}
		case *syntax.ProcSubst:
			issues = append(issues, shellUnsupportedSyntaxID+": process substitution")
		case *syntax.ArithmExp:
			issues = append(issues, shellUnsupportedSyntaxID+": arithmetic expansion")
		case *syntax.BraceExp:
			issues = append(issues, shellUnsupportedSyntaxID+": brace expansion")
		case *syntax.Redirect:
			if n.Hdoc != nil {
				issues = append(issues, shellUnsupportedSyntaxID+": here document")
			}
		}
		return len(issues) == 0
	})
	return issues
}

func isSafeCommandSubstitution(substitution *syntax.CmdSubst) bool {
	if substitution.Backquotes || substitution.TempFile || substitution.ReplyVar || len(substitution.Stmts) != 1 {
		return false
	}

	stmt := substitution.Stmts[0]
	if stmt.Negated || stmt.Background || stmt.Coprocess || stmt.Disown || len(stmt.Redirs) > 0 {
		return false
	}

	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) > 0 || len(call.Args) != 1 {
		return false
	}

	value, ok := literalWordValue(call.Args[0])
	return ok && value == "pwd"
}

func literalWordValue(word *syntax.Word) (string, bool) {
	if word == nil || len(word.Parts) != 1 {
		return "", false
	}
	lit, ok := word.Parts[0].(*syntax.Lit)
	if !ok {
		return "", false
	}
	return lit.Value, true
}

func tokenizeShell(command string) ([]string, []string) {
	var tokens []string
	var current strings.Builder
	issues := shellExpansionIssues(command)
	var quote rune
	escaped := false
	tokenStarted := false

	flush := func() {
		if tokenStarted || current.Len() > 0 {
			tokens = append(tokens, current.String())
			current.Reset()
			tokenStarted = false
		}
	}

	for i := 0; i < len(command); {
		r, width := utf8.DecodeRuneInString(command[i:])
		if escaped {
			current.WriteRune(r)
			tokenStarted = true
			escaped = false
			i += width
			continue
		}

		if quote == 0 && r == '#' && !tokenStarted {
			break
		}

		switch {
		case r == '\\' && quote != '\'':
			escaped = true
			tokenStarted = true
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				current.WriteRune(r)
			}
			tokenStarted = true
		case r == '\'' || r == '"':
			quote = r
			tokenStarted = true
		case isShellWhitespace(r):
			flush()
		case isShellOperatorStart(command, i, r):
			flush()
			operator, operatorWidth := readShellOperator(command[i:])
			tokens = append(tokens, operator)
			i += operatorWidth
			continue
		default:
			current.WriteRune(r)
			tokenStarted = true
		}
		i += width
	}

	if escaped {
		current.WriteRune('\\')
	}
	if quote != 0 {
		issues = append(issues, shellUnsupportedSyntaxID+": unterminated quote")
	}
	flush()

	return tokens, issues
}

func shellExpansionIssues(command string) []string {
	if strings.Contains(command, "<(") || strings.Contains(command, ">(") {
		return []string{shellUnsupportedSyntaxID + ": shell expansion"}
	}
	return nil
}

func isShellWhitespace(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\r'
}

func isShellOperatorStart(command string, index int, r rune) bool {
	if strings.ContainsRune(";|&<>", r) {
		return true
	}
	return r >= '0' && r <= '9' && index+1 < len(command) && (command[index+1] == '>' || command[index+1] == '<')
}

func readShellOperator(input string) (string, int) {
	if len(input) >= 2 {
		two := input[:2]
		switch two {
		case "&&", "||", ">>", "<<", "<>", "&>":
			return two, 2
		}
	}
	if len(input) >= 3 && input[0] >= '0' && input[0] <= '9' && (input[1] == '>' || input[1] == '<') && input[2] == '>' {
		return input[:3], 3
	}
	if len(input) >= 2 && input[0] >= '0' && input[0] <= '9' && (input[1] == '>' || input[1] == '<') {
		return input[:2], 2
	}
	return input[:1], 1
}

func splitShellStages(tokens []string) ([]shellStage, []string) {
	var stages []shellStage
	var current shellStage
	var issues []string

	flush := func(operator string) {
		if len(current.Tokens) > 0 || len(current.Redirects) > 0 {
			current.Operator = operator
			stages = append(stages, current)
			current = shellStage{}
		}
	}

	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		if isStageSeparator(token) {
			flush(token)
			continue
		}
		if isRedirectOperator(token) {
			redirect := shellRedirect{Operator: token}
			if i+1 < len(tokens) && !isShellControlOperator(tokens[i+1]) {
				redirect.Target = tokens[i+1]
				i++
			} else {
				issues = append(issues, shellUnsupportedSyntaxID+": redirect without target")
			}
			current.Redirects = append(current.Redirects, redirect)
			continue
		}
		current.Tokens = append(current.Tokens, token)
	}
	flush("")

	return stages, issues
}

func unwrapShellStage(stage shellStage) ([]shellStage, []string) {
	if len(stage.Tokens) == 0 {
		return []shellStage{stage}, nil
	}

	tokens := stage.Tokens
	switch normalizedCommandName(tokens[0]) {
	case "bash", "sh", "zsh":
		if script, ok := shellWrapperScript(tokens[1:]); ok {
			parsed := decomposeShellCommand(script)
			if len(parsed.Stages) == 0 {
				return []shellStage{{Tokens: []string{script}, Operator: stage.Operator, Redirects: stage.Redirects}}, parsed.Issues
			}
			parsed.Stages[len(parsed.Stages)-1].Operator = stage.Operator
			parsed.Stages[0].Redirects = append(stage.Redirects, parsed.Stages[0].Redirects...)
			return parsed.Stages, parsed.Issues
		}
	case "eval":
		if len(tokens) > 1 {
			parsed := decomposeShellCommand(strings.Join(tokens[1:], " "))
			if len(parsed.Stages) > 0 {
				parsed.Stages[len(parsed.Stages)-1].Operator = stage.Operator
				parsed.Stages[0].Redirects = append(stage.Redirects, parsed.Stages[0].Redirects...)
				return parsed.Stages, parsed.Issues
			}
			return []shellStage{stage}, parsed.Issues
		}
	case "command":
		if unwrapped, ok := unwrapCommandBuiltin(tokens); ok {
			stage.Tokens = unwrapped
			return []shellStage{stage}, nil
		}
	case "sudo", "doas", "nohup":
		if unwrapped, ok := unwrapLeadingOptions(tokens[1:]); ok {
			stage.Tokens = unwrapped
			return []shellStage{stage}, nil
		}
	case "env":
		if unwrapped, ok := unwrapEnvCommand(tokens[1:]); ok {
			stage.Tokens = unwrapped
			return []shellStage{stage}, nil
		}
	case "nice":
		if unwrapped, ok := unwrapNiceCommand(tokens[1:]); ok {
			stage.Tokens = unwrapped
			return []shellStage{stage}, nil
		}
	case "xargs":
		if unwrapped, ok := unwrapXargsCommand(tokens[1:]); ok {
			stage.Tokens = unwrapped
			return []shellStage{stage}, nil
		}
	}

	return []shellStage{stage}, nil
}

func normalizedCommandName(name string) string {
	return strings.ToLower(filepath.Base(name))
}

func shellWrapperScript(args []string) (string, bool) {
	for i, arg := range args {
		if arg == shellOptionTerminator {
			continue
		}
		if arg == "-c" {
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", false
		}
		if strings.HasPrefix(arg, "-") && strings.Contains(arg, "c") {
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", false
		}
		if !strings.HasPrefix(arg, "-") {
			return "", false
		}
	}
	return "", false
}

func unwrapCommandBuiltin(tokens []string) ([]string, bool) {
	if len(tokens) < 2 {
		return nil, false
	}
	i := 1
	for i < len(tokens) && strings.HasPrefix(tokens[i], "-") {
		i++
	}
	if i >= len(tokens) {
		return nil, false
	}
	return tokens[i:], true
}

func unwrapLeadingOptions(args []string) ([]string, bool) {
	for i, arg := range args {
		if arg == shellOptionTerminator {
			if i+1 < len(args) {
				return args[i+1:], true
			}
			return nil, false
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return args[i:], true
	}
	return nil, false
}

func unwrapEnvCommand(args []string) ([]string, bool) {
	for i, arg := range args {
		if arg == shellOptionTerminator {
			if i+1 < len(args) {
				return args[i+1:], true
			}
			return nil, false
		}
		if strings.HasPrefix(arg, "-") || strings.Contains(arg, "=") {
			continue
		}
		return args[i:], true
	}
	return nil, false
}

func unwrapNiceCommand(args []string) ([]string, bool) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == shellOptionTerminator {
			if i+1 < len(args) {
				return args[i+1:], true
			}
			return nil, false
		}
		if arg == "-n" {
			i++
			continue
		}
		if strings.HasPrefix(arg, "-n") || strings.HasPrefix(arg, "--adjustment") {
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return args[i:], true
	}
	return nil, false
}

func unwrapXargsCommand(args []string) ([]string, bool) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == shellOptionTerminator {
			if i+1 < len(args) {
				return args[i+1:], true
			}
			return nil, false
		}
		if xargsOptionConsumesValue(arg) {
			i++
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return args[i:], true
	}
	return nil, false
}

func xargsOptionConsumesValue(arg string) bool {
	switch arg {
	case "-I", "-L", "-n", "-P", "-s", "-E":
		return true
	default:
		return false
	}
}

func isStageSeparator(token string) bool {
	return token == "|" || token == "&&" || token == "||" || token == ";" || token == "&"
}

func isShellControlOperator(token string) bool {
	return isStageSeparator(token) || isRedirectOperator(token)
}

func isRedirectOperator(token string) bool {
	if token == ">" || token == "<" || token == ">>" || token == "<<" || token == "<>" || token == "&>" {
		return true
	}
	if len(token) >= 2 && token[0] >= '0' && token[0] <= '9' && (token[1] == '>' || token[1] == '<') {
		return true
	}
	return false
}
