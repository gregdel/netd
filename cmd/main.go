package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/gregdel/netd/lib/fw"
	"github.com/gregdel/netd/lib/netd"
)

func main() {
	fmt.Println("Starting netd...")
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}
	fmt.Println("All done !")
}

func run() error {
	netnsPath := flag.String("netnsPath", "", "netns path (optional)")
	runtimeDirectory := flag.String("runtimeDirectory", "/run/netd", "netd runtime directory")
	firewallRulesPath := flag.String("firewallRulesFile", "fw_rules.json", "firewall rules file name")
	flag.Parse()

	config := &netd.Config{
		FirewallConfig: &fw.Config{
			NetnsPath:        *netnsPath,
			RuntimeDirectory: *runtimeDirectory,
			RulesFilePath:    *firewallRulesPath,
		},
	}

	// Create the runtime directory
	if err := os.Mkdir(*runtimeDirectory, os.ModePerm); err != nil {
		return err
	}
	defer os.RemoveAll(*runtimeDirectory)

	netd := netd.New(config)
	if err := netd.Init(); err != nil {
		return err
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGUSR1)

	for {
		sig := <-sigs
		switch sig {
		case syscall.SIGINT:
			// Quit
			return nil
		case syscall.SIGUSR1:
			if err := netd.ReloadFirewall(); err != nil {
				fmt.Printf("error while reloading config: %s\n", err.Error())
			}
		}
	}
}
