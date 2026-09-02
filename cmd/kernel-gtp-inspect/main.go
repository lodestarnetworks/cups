// kernel-gtp-inspect prints the read-only Linux GTPv1-U PDP context table for
// one interface. It is intended for operator diagnostics and never mutates
// links, routes, sockets, or PDP contexts.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/lodestarnetworks/cups/internal/kernelgtp"
)

type contextSnapshot struct {
	UEIPv4       string `json:"ueIPv4"`
	PeerIPv4     string `json:"peerIPv4"`
	IncomingTEID uint32 `json:"incomingTEID"`
	OutgoingTEID uint32 `json:"outgoingTEID"`
}

type snapshot struct {
	Interface string            `json:"interface"`
	Index     int               `json:"index"`
	Count     int               `json:"count"`
	Contexts  []contextSnapshot `json:"contexts"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	interfaceName := flag.String("interface", "", "Linux GTP interface to inspect")
	pretty := flag.Bool("pretty", false, "indent JSON output")
	flag.Parse()

	if *interfaceName == "" {
		return errors.New("--interface is required")
	}
	link, err := net.InterfaceByName(*interfaceName)
	if err != nil {
		return fmt.Errorf("resolve GTP interface %q: %w", *interfaceName, err)
	}
	controller, err := kernelgtp.Open()
	if err != nil {
		return fmt.Errorf("open kernel GTP netlink controller: %w", err)
	}
	defer controller.Close()

	contexts, err := controller.ListContexts(uint32(link.Index))
	if err != nil {
		return fmt.Errorf("list contexts for %q: %w", *interfaceName, err)
	}
	result := snapshot{
		Interface: *interfaceName,
		Index:     link.Index,
		Count:     len(contexts),
		Contexts:  make([]contextSnapshot, 0, len(contexts)),
	}
	for _, context := range contexts {
		result.Contexts = append(result.Contexts, contextSnapshot{
			UEIPv4:       context.UEIPv4.String(),
			PeerIPv4:     context.PeerIPv4.String(),
			IncomingTEID: context.IncomingTEID,
			OutgoingTEID: context.OutgoingTEID,
		})
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if *pretty {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(result)
}
