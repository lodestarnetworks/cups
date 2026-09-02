// kernel-gtp-lab creates one disposable Linux GTP endpoint for isolated
// benchmarks. It is a direct-netlink test peer, not an SGW-U implementation.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/lodestarnetworks/cups/internal/kernelgtp"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	name := flag.String("name", "", "GTP interface name")
	ownershipFile := flag.String("ownership-file", "", "absolute persistent ownership-token file")
	roleName := flag.String("role", "", "kernel GTP role: ggsn or sgsn")
	localText := flag.String("local", "", "local outer IPv4 address")
	peerText := flag.String("peer", "", "allowed peer outer IPv4 address")
	ueText := flag.String("ue", "", "UE IPv4 address")
	incomingTEID := flag.Uint("incoming-teid", 0, "locally allocated incoming TEID")
	outgoingTEID := flag.Uint("outgoing-teid", 0, "peer-allocated outgoing TEID")
	interfaceAddressText := flag.String("interface-address", "", "IPv4 /32 assigned to the GTP interface")
	routePrefixText := flag.String("route-prefix", "", "inner IPv4 prefix routed to the GTP interface")
	hashSize := flag.Uint("hash-size", uint(kernelgtp.DefaultHashSize), "kernel PDP hash size")
	mtu := flag.Uint("mtu", uint(kernelgtp.DefaultMTU), "GTP interface MTU")
	socketBuffer := flag.Int("socket-buffer-bytes", kernelgtp.DefaultSocketBufferBytes, "GTP-U socket buffer request")
	flag.Parse()

	if os.Getenv("SGW_NEXT_ISOLATED_GTP_LAB") != "1" {
		return errors.New("kernel-gtp-lab refuses to run unless SGW_NEXT_ISOLATED_GTP_LAB=1")
	}
	if os.Geteuid() != 0 {
		return errors.New("kernel-gtp-lab requires root inside a disposable network namespace")
	}
	parseAddress := func(raw, label string) (netip.Addr, error) {
		address, err := netip.ParseAddr(raw)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("%s: %w", label, err)
		}
		return address.Unmap(), nil
	}
	local, err := parseAddress(*localText, "local outer address")
	if err != nil {
		return err
	}
	peer, err := parseAddress(*peerText, "peer outer address")
	if err != nil {
		return err
	}
	ue, err := parseAddress(*ueText, "UE address")
	if err != nil {
		return err
	}
	interfaceAddress, err := parseAddress(*interfaceAddressText, "GTP interface address")
	if err != nil {
		return err
	}
	routePrefix, err := netip.ParsePrefix(*routePrefixText)
	if err != nil {
		return fmt.Errorf("route prefix: %w", err)
	}
	var role kernelgtp.Role
	switch *roleName {
	case "ggsn":
		role = kernelgtp.RoleGGSN
	case "sgsn":
		role = kernelgtp.RoleSGSN
	default:
		return errors.New("role must be ggsn or sgsn")
	}
	if *incomingTEID == 0 || *outgoingTEID == 0 || *incomingTEID > uint(^uint32(0)) || *outgoingTEID > uint(^uint32(0)) {
		return errors.New("incoming and outgoing TEIDs must fit non-zero uint32 values")
	}
	if *hashSize > uint(^uint32(0)) || *mtu > uint(^uint32(0)) {
		return errors.New("hash size and MTU must fit uint32 values")
	}

	controller, err := kernelgtp.Open()
	if err != nil {
		return err
	}
	link, err := controller.CreateLink(kernelgtp.LinkConfig{
		Name: *name, OwnershipFile: *ownershipFile,
		LocalIPv4: local, AllowedPeers: []netip.Addr{peer}, Role: role,
		HashSize: uint32(*hashSize), MTU: uint32(*mtu), SocketBufferBytes: *socketBuffer,
	})
	if err != nil {
		_ = controller.Close()
		return err
	}
	if err := controller.ConfigureIPv4(link, interfaceAddress, routePrefix); err != nil {
		return errors.Join(err, controller.Close())
	}
	if err := controller.AddContext(kernelgtp.Context{
		LinkIndex: link.Index, UEIPv4: ue, PeerIPv4: peer,
		IncomingTEID: uint32(*incomingTEID), OutgoingTEID: uint32(*outgoingTEID),
	}); err != nil {
		return errors.Join(err, controller.Close())
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Printf("kernel GTP lab endpoint ready: interface=%s role=%s local=%s peer=%s UE=%s\n", link.Name, role, local, peer, ue)
	<-ctx.Done()
	return controller.Close()
}
