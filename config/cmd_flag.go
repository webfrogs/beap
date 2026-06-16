package config

import (
	"flag"
	"fmt"
	"strings"
)

type cmdParam struct {
	showVersion  bool
	configFile   string
	tproxyPort   string
	socks5Addr   string
	programNames programNamesFlag
}

var parsedCmdParam = new(cmdParam)

func parseCmdFlag() {
	flag.BoolVar(&parsedCmdParam.showVersion, "v", false, "Show current version.")
	flag.StringVar(&parsedCmdParam.configFile, "f", "", "specify configuration file")
	flag.StringVar(&parsedCmdParam.tproxyPort, "tproxy-port", "2089", "transparent proxy listen port")
	flag.StringVar(&parsedCmdParam.socks5Addr, "socks5-addr", "127.0.0.1:1091", "SOCKS5 proxy address")
	flag.Var(&parsedCmdParam.programNames, "program", "program name to proxy; repeat to proxy multiple programs")

	flag.Parse()
}

type programNamesFlag struct {
	values []string
	set    bool
}

func (f *programNamesFlag) String() string {
	if f == nil {
		return ""
	}
	return strings.Join(f.values, ",")
}

func (f *programNamesFlag) Set(value string) error {
	name := strings.TrimSpace(value)
	if name == "" {
		return fmt.Errorf("program name cannot be empty")
	}
	if !f.set {
		f.values = nil
		f.set = true
	}
	f.values = append(f.values, name)
	return nil
}
