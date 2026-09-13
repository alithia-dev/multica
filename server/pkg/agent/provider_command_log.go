package agent

import (
	"log/slog"
	"os/exec"
	"strings"
	"sync"
)

const redactedAgentCommandArg = "<redacted>"

const maxLoggedAgentCommandFlagLen = 64

// agentCommandLogArgs describes adapter-owned argv. Only positionals proven to
// be fixed adapter subcommands may survive logging; every value remains
// redacted, including values supplied through custom arguments.
type agentCommandLogArgs struct {
	invocationArgs     []string
	trustedPositionals map[int]string
	trustedFlags       map[int]string
}

func newAgentCommandLogArgs(invocationArgs []string, trustedPositionals, trustedFlags map[int]string) agentCommandLogArgs {
	return agentCommandLogArgs{
		invocationArgs:     invocationArgs,
		trustedPositionals: trustedPositionals,
		trustedFlags:       trustedFlags,
	}
}

// logAgentCommand records useful provider diagnostics without persisting
// prompts, route identifiers, credentials, tokens, or other argument values.
// Trust is mapped from the adapter's source argv onto the final exec.Cmd and
// fails closed if the command was rewritten unexpectedly.
func logAgentCommand(logger *slog.Logger, provider string, cmd *exec.Cmd, source agentCommandLogArgs) {
	if cmd == nil {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}

	args := []string{}
	if len(cmd.Args) > 1 {
		args = cmd.Args[1:]
	}
	trustedPositionals, trustedFlags := trustedAgentCommandPositions(args, source)
	logger.Info("agent command",
		"provider", provider,
		"exec", cmd.Path,
		"args", redactAgentCommandArgs(args, trustedPositionals, trustedFlags),
		"arg_count", len(args),
	)
}

func trustedAgentCommandPositions(finalArgs []string, source agentCommandLogArgs) (map[int]struct{}, map[int]struct{}) {
	if len(finalArgs) != len(source.invocationArgs) {
		return nil, nil
	}
	for i, arg := range source.invocationArgs {
		if finalArgs[i] != arg {
			return nil, nil
		}
	}

	trustedPositionals := make(map[int]struct{}, len(source.trustedPositionals))
	for index, value := range source.trustedPositionals {
		if index >= 0 && index < len(source.invocationArgs) && source.invocationArgs[index] == value {
			trustedPositionals[index] = struct{}{}
		}
	}
	trustedFlags := make(map[int]struct{}, len(source.trustedFlags))
	for index, value := range source.trustedFlags {
		if index >= 0 && index < len(source.invocationArgs) && source.invocationArgs[index] == value {
			trustedFlags[index] = struct{}{}
		}
	}
	return trustedPositionals, trustedFlags
}

func redactAgentCommandArgs(args []string, trustedPositionals, trustedFlags map[int]struct{}) []string {
	redacted := make([]string, len(args))
	for i, arg := range args {
		if _, ok := trustedPositionals[i]; ok {
			redacted[i] = arg
			continue
		}
		if _, ok := trustedFlags[i]; ok {
			if flag, safe := safeAgentCommandFlagName(arg); safe {
				redacted[i] = flag
				continue
			}
		}
		redacted[i] = redactedAgentCommandArg
	}
	return redacted
}

func safeAgentCommandFlagName(arg string) (string, bool) {
	flag := arg
	if equals := strings.IndexByte(flag, '='); equals > 0 {
		flag = flag[:equals]
	}
	if len(flag) == 2 && flag[0] == '-' && isASCIIAlpha(flag[1]) {
		return flag, true
	}
	if len(flag) < 3 || len(flag) > maxLoggedAgentCommandFlagLen || !strings.HasPrefix(flag, "--") || !isASCIIAlpha(flag[2]) {
		return "", false
	}
	for i := 3; i < len(flag); i++ {
		ch := flag[i]
		if !isASCIIAlpha(ch) && (ch < '0' || ch > '9') && ch != '.' && ch != '_' && ch != '-' {
			return "", false
		}
	}
	return flag, true
}

func isASCIIAlpha(ch byte) bool {
	return ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z'
}

// redactedSubprocessLogWriter preserves the fact that stderr was produced but
// never persists subprocess-controlled content. OpenClaw output may contain
// prompts, tool output, financial rows, balances, or credentials.
type redactedSubprocessLogWriter struct {
	logger *slog.Logger
	prefix string
	once   sync.Once
}

func newRedactedSubprocessLogWriter(logger *slog.Logger, prefix string) *redactedSubprocessLogWriter {
	if logger == nil {
		logger = slog.Default()
	}
	return &redactedSubprocessLogWriter{logger: logger, prefix: prefix}
}

func (w *redactedSubprocessLogWriter) Write(p []byte) (int, error) {
	w.once.Do(func() {
		w.logger.Debug(w.prefix + "output suppressed")
	})
	return len(p), nil
}
