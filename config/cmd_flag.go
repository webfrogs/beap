package config

import "flag"

type cmdParam struct {
	showVersion  bool
	configFile   string
	tproxyPort   string
	sock5Addr    string
	programNames string
}

var parsedCmdParam = new(cmdParam)

func parseCmdFlag() {
	flag.BoolVar(&parsedCmdParam.showVersion, "v", false, "Show current version.")
	flag.StringVar(&parsedCmdParam.configFile, "f", "", "specify configuration file")
	flag.StringVar(&parsedCmdParam.tproxyPort, "tproxy-port", "2089", "transparent proxy listen port")
	flag.StringVar(&parsedCmdParam.sock5Addr, "sock5-addr", "192.168.110.32:1091", "SOCKS5 proxy address")
	flag.StringVar(&parsedCmdParam.programNames, "program-names", "agy", "comma-separated process names to proxy")

	flag.Parse()
}
