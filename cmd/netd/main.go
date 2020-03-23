package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

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
	netnsPath := "/var/run/netns/netd"

	netd := netd.New(netnsPath)

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
