package config

import "flag"

type cmdParam struct {
	showVersion  bool
	configFile   string
	tproxyPort   string
	socks5Addr   string
	programNames string
}

var parsedCmdParam = new(cmdParam)

func parseCmdFlag() {
	flag.BoolVar(&parsedCmdParam.showVersion, "v", false, "Show current version.")
	flag.StringVar(&parsedCmdParam.configFile, "f", "", "specify configuration file")
	flag.StringVar(&parsedCmdParam.tproxyPort, "tproxy-port", "2089", "transparent proxy listen port")
	flag.StringVar(&parsedCmdParam.socks5Addr, "socks5-addr", "127.0.0.1:1091", "SOCKS5 proxy address")
	flag.StringVar(&parsedCmdParam.programNames, "program-names", "agy", "comma-separated process names to proxy")

	flag.Parse()
}
