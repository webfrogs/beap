package config

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

var Data *ConfigData

type ConfigData struct {
	TproxyPort   string
	Sock5Addr    string
	ProgramNames []string
}

func init() {
	parseCmdFlag()

	if parsedCmdParam.showVersion {
		fmt.Printf("==> [beap version] goRuntime=%s gitHash=%s buildTime=%s\n", runtime.Version(), GitHash, BuildTime)
		os.Exit(0)
	}
	parseConfigFile()
}

func parseConfigFile() {
	// TODO: implement
	Data = &ConfigData{
		TproxyPort:   parsedCmdParam.tproxyPort,
		Sock5Addr:    parsedCmdParam.sock5Addr,
		ProgramNames: parseProgramNames(parsedCmdParam.programNames),
	}
}

func parseProgramNames(value string) []string {
	parts := strings.Split(value, ",")
	names := make([]string, 0, len(parts))
	for _, part := range parts {
		name := strings.TrimSpace(part)
		if name == "" {
			continue
		}
		names = append(names, name)
	}
	return names
}
