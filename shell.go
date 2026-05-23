package guardian

import (
	"strings"
	"unicode/utf8"
)

const (
	actionCommandExecLocal   = "command.exec_local"
	actionCommandObfuscated  = "command.obfuscated"
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
	parsed := decomposeShellCommand(command)
	if len(parsed.Issues) > 0 {
		return actionCommandObfuscated
	}
	return actionCommandExecLocal
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
