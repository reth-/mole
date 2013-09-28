package main

import (
	"github.com/jessevdk/go-flags"
	"os"
	"path"
	"text/template"
)

type bashcompCommand struct{}

var bashcompParser *flags.Parser
var compTpl = template.Must(template.New("bashcomp").Parse(compTplStr))
var compTplStr = `_mole_tunnels() {
	compgen -W "$(cat {{.CacheFile}})" -- $cur
}

_mole() {
	local cur
	local prev

	COMPREPLY=()
	cur=${COMP_WORDS[COMP_CWORD]}
	prev=${COMP_WORDS[COMP_CWORD-1]}

	case "$prev" in
		mole)
			COMPREPLY=($(compgen -W "{{ range .AllCommands }}{{.}} {{ end }}" -- $cur))
			;;
		{{ range .TunnelCommands }}
		{{.}})
			COMPREPLY=($(_mole_tunnels))
			;;
		{{end}}
		{{ range .FileCommands }}
		{{.}})
			COMPREPLY=($(compgen -f -X \!\*.ini -- $cur))
			;;
		{{end}}
	esac

	return 0
}

complete -F _mole mole
`

func init() {
	cmd := bashcompCommand{}
	bashcompParser = globalParser.AddCommand("bashcomp", msgBashcompShort, msgBashcompLong, &cmd)
}

func (c *bashcompCommand) Execute(args []string) error {
	setup()

	compData := struct {
		CacheFile      string
		AllCommands    []string
		TunnelCommands []string
		FileCommands   []string
	}{
		path.Join(globalOpts.Home, "tunnels.cache"),
		[]string{"dig", "ls", "push", "register", "show", "test", "upgrade", "version", "rm"},
		[]string{"dig", "show", "test", "rm"},
		[]string{"push"},
	}

	_ = compTpl.Execute(os.Stdout, compData)
	return nil
}