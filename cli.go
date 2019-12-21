package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/integrii/flaggy"
)

const (
	historyLayout = "2006-01-02 15:04:05"
)

var (
	historyTime time.Time

	flagHelp        bool
	flagNoColor     bool
	flagNoClearClip bool
	flagNoAutoSync  bool
	flagTime        string
	flagFile        string
)

var (
	versionCmd     = flaggy.NewSubcommand("version")
	genCmd         = flaggy.NewSubcommand("gen")
	lpassImportCmd = flaggy.NewSubcommand("lpassimport")
)

func parseCli() {
	defaultFilePath := ".bpass"
	homeDir, err := os.UserHomeDir()
	if err == nil && len(homeDir) != 0 {
		defaultFilePath = filepath.Join(homeDir, defaultFilePath)
	}
	flagFile = defaultFilePath

	parser := flaggy.NewParser("bpass")
	parser.Bool(&flagNoColor, "", "no-color", "Turn off color output")
	parser.Bool(&flagNoAutoSync, "", "no-sync", "Do not sync the file automatically")
	parser.Bool(&flagNoClearClip, "", "no-clear-clip", "Do not clear clipboard on exit")
	parser.Bool(&flagHelp, "h", "help", "Show help")
	parser.String(&flagTime, "t", "time", "Open the file read-only at a time in the past (YYYY-MM-DD HH:mm:ss)")
	parser.String(&flagFile, "f", "file", "The file to open (can be set by $BPASS)")

	versionCmd.Description = "print version and exit"
	lpassImportCmd.Description = "import lastpass csv by running `lpass export`"
	genCmd.Description = "generate a password"

	parser.AdditionalHelpAppend = "bpass respects $BPASS, $EDITOR, $PINENTRY env vars\n$PINENTRY can be set to none to prevent it from using pinentry"

	parser.ShowHelpWithHFlag = false
	parser.ShowHelpOnUnexpected = false

	// Configure some bits about the lib
	parser.DisableShowVersionWithVersion()
	if err := parser.SetHelpTemplate(helpTemplate); err != nil {
		// This should never occur
		panic(err)
	}

	parser.AttachSubcommand(versionCmd, 1)
	parser.AttachSubcommand(genCmd, 1)
	parser.AttachSubcommand(lpassImportCmd, 1)
	parser.Parse()

	if flagFile == defaultFilePath {
		envFile := os.Getenv("BPASS")
		if len(envFile) != 0 {
			flagFile = envFile
		}
	}
	if len(flagTime) != 0 {
		var err error
		historyTime, err = time.Parse(historyLayout, flagTime)
		if err != nil {
			fmt.Println("failed to parse the date flag, format:", historyLayout)
			os.Exit(1)
		}
	}

	if flagHelp {
		parser.ShowHelp()
		os.Exit(0)
	}
}

var helpTemplate = `Usage:
  {{.CommandName}} [flags]{{if .Subcommands}} [command]{{end}}
{{- if .Subcommands}}

Commands:
  {{range .Subcommands -}}
  {{.LongName}}
  {{end -}}
{{- end}}
{{- if .Flags}}
Flags:
  {{- range .Flags}}
  {{if .ShortName}}-{{.ShortName}}{{if .LongName}}, {{else}}  {{end}}{{else}}    {{end}}{{printf "--%-15s" .LongName}}
  {{- if .Description}} {{.Description}}{{end}}
  {{- if and (.DefaultValue) (not (eq "false" .DefaultValue))}} ({{.DefaultValue}}){{end}}
  {{- end -}}
{{- end}}{{if .AppendMessage}}

{{.AppendMessage}}
{{- end}}
`
