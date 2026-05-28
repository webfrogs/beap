package config

import (
	"fmt"
	"os"
	"runtime"
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
		TproxyPort:   "2089",
		Sock5Addr:    "192.168.110.32:1091",
		ProgramNames: []string{"agy"},
	}
}
