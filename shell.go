package guardian

import (
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	actionCommandExecLocal   = "command.exec_local"
	actionCommandExecRemote  = "command.exec_remote"
	actionCommandObfuscated  = "command.obfuscated"
	actionSecretExfiltrate   = "secret.exfiltrate" //nolint:gosec // Action names mention secrets but are policy taxonomy, not credentials.
	shellUnsupportedSyntaxID = "unsupported shell syntax"
)

type shellCommand struct {
	Raw    string
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

func classifyExecCommand(command string) string {
	actions := classifyExecCommandActions(command)
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

func classifyExecCommandActions(command string) []string {
	parsed := decomposeShellCommand(command)
	if len(parsed.Issues) > 0 {
		return []string{actionCommandObfuscated}
	}

	if len(parsed.Stages) == 0 {
		return []string{actionCommandExecLocal}
	}

	stageActions := make([]string, 0, len(parsed.Stages)+1)
	for _, stage := range parsed.Stages {
		stageActions = append(stageActions, classifyShellStage(stage))
	}
	if compositionAction := detectCompositionAction(parsed.Stages, stageActions); compositionAction != "" {
		stageActions = append(stageActions, compositionAction)
	}

	return stageActions
}

func classifyShellStage(stage shellStage) string { //nolint:gocyclo // Command family classification is intentionally centralized.
	if len(stage.Tokens) == 0 {
		if hasWriteRedirect(stage.Redirects) {
			return actionCommandWrite
		}
		return actionCommandRead
	}

	tokens := stage.Tokens
	name := strings.ToLower(tokens[0])
	args := tokens[1:]

	switch name {
	case "git":
		return classifyGitCommand(args)
	case "rm", "rmdir", "unlink":
		if isDangerousDelete(args) {
			return actionCommandDangerousDelete
		}
		return actionFileDelete
	case "mv", "cp", "mkdir", "touch", "tee":
		return actionCommandWrite
	case "sed":
		if hasShortFlag(args, "i") || hasLongFlag(args, "in-place") {
			return actionCommandWrite
		}
		return actionCommandRead
	case "find":
		if findMutates(args) {
			return actionCommandWrite
		}
		return actionCommandRead
	case "grep", "rg", "cat", "ls", "pwd", "wc", "head", "tail", "stat":
		if stageReadsSensitivePath(name, args) {
			return actionSecretRead
		}
		if hasWriteRedirect(stage.Redirects) {
			return actionCommandWrite
		}
		return actionCommandRead
	case "curl", "wget":
		return classifyNetworkCommand(name, args)
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
	case "get", "options":
		return actionNetworkRead
	case "post", "put", "patch", "delete":
		return actionNetworkWrite
	default:
		if hasWriteRedirect(stage.Redirects) {
			return actionCommandWrite
		}
		return actionCommandExecLocal
	}
}

const actionCommandDangerousDelete = "command.dangerous_delete"

func commandActionRank(actionType string) int {
	switch actionType {
	case actionCommandExecRemote, actionCommandObfuscated, actionCommandDangerousDelete, actionGitHistoryRewrite, actionSecretExfiltrate:
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

func detectCompositionAction(stages []shellStage, actions []string) string {
	for i := range len(stages) - 1 {
		if stages[i].Operator != "|" {
			continue
		}
		if actions[i] == actionNetworkRead && isExecutionSink(stages[i+1]) {
			return actionCommandExecRemote
		}
		if actions[i] == actionSecretRead && actions[i+1] == actionNetworkWrite {
			return actionSecretExfiltrate
		}
		if isDecodeStage(stages[i]) {
			return actionCommandObfuscated
		}
	}
	return ""
}

func isExecutionSink(stage shellStage) bool {
	if len(stage.Tokens) == 0 {
		return false
	}
	switch strings.ToLower(stage.Tokens[0]) {
	case "bash", "sh", "zsh", "fish", "python", "python3", "py", "perl", "ruby", "node", "deno", "php":
		return true
	default:
		return false
	}
}

func isDecodeStage(stage shellStage) bool {
	if len(stage.Tokens) == 0 {
		return false
	}
	name := strings.ToLower(stage.Tokens[0])
	switch name {
	case "base64", "xxd", "openssl", "certutil":
		return hasAnyArg(stage.Tokens[1:], "-d", "--decode", "-decode", "enc") || hasShortFlag(stage.Tokens[1:], "d")
	default:
		return false
	}
}

func stageReadsSensitivePath(command string, args []string) bool {
	switch command {
	case "cat", "head", "tail", "stat", "wc":
		for _, arg := range args {
			if isShellFileArg(arg) && isSensitivePath(normalizeRequestPath(arg, "")) {
				return true
			}
		}
	case "grep", "rg":
		for _, arg := range args[1:] {
			if isShellFileArg(arg) && isSensitivePath(normalizeRequestPath(arg, "")) {
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
	case "restore", "clean":
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
		if arg == "--" && i+1 < len(args) {
			return true
		}
	}
	return false
}

func classifyNetworkCommand(name string, args []string) string { //nolint:gocyclo // HTTP clients expose several equivalent write indicators.
	if name == "wget" && (hasLongFlag(args, "post-data") || hasLongFlag(args, "post-file") || hasLongFlag(args, "body-data") || hasLongFlag(args, "body-file")) {
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
		if arg == "--" {
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

func findMutates(args []string) bool {
	for i, arg := range args {
		switch arg {
		case "-delete", "-exec", "-execdir":
			return true
		case "-ok", "-okdir":
			return true
		}
		if i > 0 && (arg == ">" || arg == ">>") {
			return true
		}
	}
	return false
}

func hasWriteRedirect(redirects []shellRedirect) bool {
	for _, redirect := range redirects {
		if strings.Contains(redirect.Operator, ">") {
			return true
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
		case "/", "*", "/*", "~", "$HOME", "${HOME}", ".":
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
	parsed := shellCommand{Raw: command}
	tokens, issues := tokenizeShell(command)
	parsed.Issues = append(parsed.Issues, issues...)
	if len(tokens) == 0 {
		return parsed
	}

	stages, issues := splitShellStages(tokens)
	parsed.Issues = append(parsed.Issues, issues...)
	for _, stage := range stages {
		parsed.Stages = append(parsed.Stages, unwrapShellStage(stage)...)
	}

	return parsed
}

func tokenizeShell(command string) ([]string, []string) {
	var tokens []string
	var current strings.Builder
	var issues []string
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

func unwrapShellStage(stage shellStage) []shellStage {
	if len(stage.Tokens) == 0 {
		return []shellStage{stage}
	}

	tokens := stage.Tokens
	switch tokens[0] {
	case "bash", "sh", "zsh":
		if script, ok := shellWrapperScript(tokens[1:]); ok {
			parsed := decomposeShellCommand(script)
			if len(parsed.Stages) == 0 {
				return []shellStage{{Tokens: []string{script}, Operator: stage.Operator, Redirects: stage.Redirects}}
			}
			parsed.Stages[len(parsed.Stages)-1].Operator = stage.Operator
			parsed.Stages[0].Redirects = append(stage.Redirects, parsed.Stages[0].Redirects...)
			return parsed.Stages
		}
	case "eval":
		if len(tokens) > 1 {
			parsed := decomposeShellCommand(strings.Join(tokens[1:], " "))
			if len(parsed.Stages) > 0 {
				parsed.Stages[len(parsed.Stages)-1].Operator = stage.Operator
				parsed.Stages[0].Redirects = append(stage.Redirects, parsed.Stages[0].Redirects...)
				return parsed.Stages
			}
		}
	case "command":
		if unwrapped, ok := unwrapCommandBuiltin(tokens); ok {
			stage.Tokens = unwrapped
			return []shellStage{stage}
		}
	}

	return []shellStage{stage}
}

func shellWrapperScript(args []string) (string, bool) {
	for i, arg := range args {
		if arg == "--" {
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
