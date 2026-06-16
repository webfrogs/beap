package config

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
)

var Data *ConfigData

type ConfigData struct {
	TproxyPort   uint16
	Socks5Addr   string
	ProgramNames []string
}

func init() {
	parseCmdFlag()

	if parsedCmdParam.showVersion {
		fmt.Printf("==> [beap version] goRuntime=%s gitHash=%s buildTime=%s\n", runtime.Version(), GitHash, BuildTime)
		os.Exit(0)
	}
	parseConfigFile()
	if err := validateConfigData(Data); err != nil {
		fmt.Fprintf(os.Stderr, "invalid config: %v\n", err)
		os.Exit(1)
	}
}

func parseConfigFile() {
	// TODO: implement
	Data = &ConfigData{
		Socks5Addr:   parsedCmdParam.socks5Addr,
		ProgramNames: parsedCmdParam.programNames.values,
	}
}

func validateConfigData(data *ConfigData) error {
	if data == nil {
		return fmt.Errorf("config data is nil")
	}
	tproxyPort, err := validatePort("tproxy port", parsedCmdParam.tproxyPort)
	if err != nil {
		return err
	}
	data.TproxyPort = tproxyPort
	if err := validateSocks5Addr(data.Socks5Addr); err != nil {
		return err
	}
	if len(data.ProgramNames) == 0 {
		return fmt.Errorf("at least one proxy process name is required")
	}
	for _, name := range data.ProgramNames {
		if name == "" {
			return fmt.Errorf("process name cannot be empty")
		}
		if len(name) > 15 {
			return fmt.Errorf("process name %q is too long for task comm, max 15 bytes", name)
		}
	}
	return nil
}

func validateSocks5Addr(addr string) error {
	if addr == "" {
		return fmt.Errorf("SOCKS5 proxy address is required")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid SOCKS5 proxy address %q: %w", addr, err)
	}
	if host == "" {
		return fmt.Errorf("invalid SOCKS5 proxy address %q: host is required", addr)
	}
	_, err = validatePort("SOCKS5 proxy port", port)
	return err
}

func validatePort(name, value string) (uint16, error) {
	port, err := strconv.ParseUint(value, 10, 16)
	if err != nil || port == 0 {
		return 0, fmt.Errorf("invalid %s %q", name, value)
	}
	return uint16(port), nil
}
