package config

import "flag"

type cmdParam struct {
	showVersion bool
	configFile  string
}

var parsedCmdParam = new(cmdParam)

func parseCmdFlag() {
	flag.BoolVar(&parsedCmdParam.showVersion, "v", false, "Show current version.")
	flag.StringVar(&parsedCmdParam.configFile, "f", "", "specify configuration file")

	flag.Parse()
}
