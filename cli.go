package main

import (
	"os"

	"github.com/integrii/flaggy"
)

var (
	flagHelp        bool
	flagNoColor     bool
	flagRevision    uint
	flagNoClearClip bool
	flagFile        string = "passwd.blob"
)

var (
	versionCmd = flaggy.NewSubcommand("version")
)

type cliContext struct {
	ctx *uiContext
}

var helpTemplate = `Usage:
  {{.CommandName}} [flags]{{if .Subcommands}} [command]{{end}}
{{- if .Subcommands}}

Commands:
  {{- range .Subcommands}}
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
{{- end}}
`

func parseCli() {
	parser := flaggy.NewParser("bpass")
	parser.Bool(&flagNoColor, "", "no-color", "Turn off color output")
	parser.Bool(&flagNoClearClip, "", "no-clear-clip", "Do not clear clipboard on exit")
	parser.Bool(&flagHelp, "h", "help", "Show help")
	parser.String(&flagFile, "f", "file", "The file to open")

	parser.ShowHelpWithHFlag = false
	parser.ShowHelpOnUnexpected = false

	// Configure some bits about the lib
	parser.DisableShowVersionWithVersion()
	if err := parser.SetHelpTemplate(helpTemplate); err != nil {
		// This should never occur
		panic(err)
	}

	parser.AttachSubcommand(versionCmd, 1)
	parser.Parse()

	if flagHelp {
		parser.ShowHelp()
		os.Exit(1)
	}
}
