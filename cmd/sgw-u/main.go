package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lodestarnetworks/cups/internal/api"
	"github.com/lodestarnetworks/cups/internal/config"
	"github.com/lodestarnetworks/cups/internal/debugserver"
	"github.com/lodestarnetworks/cups/internal/live"
	pfcptransport "github.com/lodestarnetworks/cups/internal/pfcp/transport"
	"github.com/lodestarnetworks/cups/internal/pfcp/usagereport"
	"github.com/lodestarnetworks/cups/internal/runtimeobs"
	"github.com/lodestarnetworks/cups/internal/sgwu/dataplane"
	"github.com/lodestarnetworks/cups/internal/sgwu/fastpath"
	"github.com/lodestarnetworks/cups/internal/sgwu/pfcpserver"
	"github.com/lodestarnetworks/cups/internal/sgwu/rules"
	"github.com/lodestarnetworks/cups/internal/telemetry"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "configs/sgw-u.lab.yaml", "path to strict YAML configuration")
	checkConfig := flag.Bool("check-config", false, "validate configuration and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *checkConfig {
		if _, err := config.LoadSGWU(*configPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("SGW-U configuration is valid")
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *configPath, logger); err != nil {
		logger.Error("SGW-U stopped", "error", err)
		os.Exit(1)
	}
}

func run(parent context.Context, path string, logger *slog.Logger) error {
	value, err := config.LoadSGWU(path)
	if err != nil {
		return err
	}
	pfcpListen, err := config.AddrPort(value.PFCPListen, "pfcpListen")
	if err != nil {
		return err
	}
	pfcpAdvertise, err := config.Addr(value.PFCPAdvertise, "pfcpAdvertise")
	if err != nil {
		return err
	}
	allowed, err := config.Addrs(value.AllowedSGWC, "allowedSgwc")
	if err != nil {
		return err
	}
	access, err := config.AddrPort(value.AccessGTPUListen, "accessGtpuListen")
	if err != nil {
		return err
	}
	allowedAccess, err := config.Addrs(value.AllowedAccessPeers, "allowedAccessPeers")
	if err != nil {
		return err
	}
	core, err := config.AddrPort(value.CoreGTPUListen, "coreGtpuListen")
	if err != nil {
		return err
	}
	allowedCore, err := config.Addrs(value.AllowedCorePeers, "allowedCorePeers")
	if err != nil {
		return err
	}
	retransmit, err := config.Duration(value.RetransmitTimeout, "retransmitTimeout")
	if err != nil {
		return err
	}
	reportSuppression, err := config.Duration(value.ReportSuppression, "downlinkReportSuppression")
	if err != nil {
		return err
	}
	reportTimeout, err := config.Duration(value.ReportTimeout, "downlinkReportTimeout")
	if err != nil {
		return err
	}
	associationTimeout, err := config.Duration(value.AssociationTimeout, "associationTimeout")
	if err != nil {
		return err
	}
	graceWindow, err := config.Duration(value.GraceWindow, "associationGraceWindow")
	if err != nil {
		return err
	}
	bufferClasses := make([]dataplane.BufferClassConfig, 0, len(value.DownlinkBuffering))
	for index, class := range value.DownlinkBuffering {
		holdTime, err := config.Duration(class.HoldTime, fmt.Sprintf("downlinkBuffering[%d].holdTime", index))
		if err != nil {
			return err
		}
		bufferClasses = append(bufferClasses, dataplane.BufferClassConfig{
			QCI: class.QCI, MaxPackets: class.MaxPackets, MaxBytes: class.MaxBytes,
			MaxPacketsPerBearer: class.MaxPacketsPerBearer, HoldTime: holdTime,
		})
	}
	qerBurstDuration, err := config.Duration(value.QERBurstDuration, "qerBurstDuration")
	if err != nil {
		return err
	}
	debug, err := debugserver.New(value.DebugListen)
	if err != nil {
		return err
	}
	runtimeSampler := runtimeobs.NewSampler()
	started := time.Now().UTC()
	transport := pfcptransport.DefaultConfig()
	transport.RetransmitTimeout = retransmit
	transport.MaxRetransmits = value.MaxRetransmits
	ruleStore := rules.NewStoreWithLimit(value.MaxSessions)
	server, err := pfcpserver.New(pfcpserver.Config{
		Listen: pfcpListen, Advertise: pfcpAdvertise,
		AccessUserIP: access.Addr(), CoreUserIP: core.Addr(), AllowedCP: allowed,
		StartedAt: started, ReportQueueSize: value.ReportQueueSize,
		ReportSuppression: reportSuppression, ReportTimeout: reportTimeout,
		AssociationTimeout: associationTimeout, GraceWindow: graceWindow,
		EnterpriseID: value.PFCPEnterpriseID, Transport: transport,
	}, ruleStore)
	if err != nil {
		return err
	}
	forwarder, err := dataplane.Listen(dataplane.Config{
		Access: access, Core: core,
		AllowedAccessPeers: allowedAccess, AllowedCorePeers: allowedCore,
		SocketBufferBytes: value.SocketBufferBytes,
		PacketBatchSize:   value.GTPUBatchSize,
		BufferClasses:     bufferClasses,
		QERBurstDuration:  qerBurstDuration,
	}, ruleStore)
	if err != nil {
		_ = server.Close()
		return err
	}
	if value.FastPath.Mode == "tcx" {
		accessNeighbours, err := fastPathNeighbours(value.FastPath.AccessNeighbours)
		if err != nil {
			_ = forwarder.Close()
			_ = server.Close()
			return err
		}
		coreNeighbours, err := fastPathNeighbours(value.FastPath.CoreNeighbours)
		if err != nil {
			_ = forwarder.Close()
			_ = server.Close()
			return err
		}
		kernelPath, err := fastpath.Open(fastpath.Config{
			Access:      fastpath.Side{Interface: value.FastPath.AccessInterface, LocalIP: access.Addr(), Neighbours: accessNeighbours},
			Core:        fastpath.Side{Interface: value.FastPath.CoreInterface, LocalIP: core.Addr(), Neighbours: coreNeighbours},
			MaxSessions: value.MaxSessions, MaxRules: value.FastPath.MaxRules,
		}, ruleStore)
		if err != nil {
			_ = forwarder.Close()
			_ = server.Close()
			return err
		}
		forwarder.SetFastPath(kernelPath)
	}
	forwarder.SetDownlinkReporter(server)
	server.SetSessionObserver(forwarder)
	if err := server.SetUsageSource(func() []usagereport.Measurement {
		current := forwarder.Usage()
		out := make([]usagereport.Measurement, 0, len(current))
		for _, measurement := range current {
			out = append(out, usagereport.Measurement{
				UPSEID: measurement.UPSEID, URRID: measurement.URRID,
				UplinkPackets: measurement.UplinkPackets, DownlinkPackets: measurement.DownlinkPackets,
				UplinkBytes: measurement.UplinkBytes, DownlinkBytes: measurement.DownlinkBytes,
				ThresholdEvents: measurement.ThresholdEvents,
				FirstPacket:     measurement.FirstPacket, LastPacket: measurement.LastPacket,
			})
		}
		return out
	}); err != nil {
		_ = forwarder.Close()
		_ = server.Close()
		return err
	}
	events := live.NewEventLog(200)
	events.Add("sgw-u", telemetry.SeverityInfo, "startup", "SGW-U listeners ready", map[string]string{
		"pfcp": server.LocalAddr().String(), "s1-u": forwarder.AccessAddr().String(), "s5-u": forwarder.CoreAddr().String(), "dataplane": forwarder.Mode(),
	})
	provider := live.NewUserProvider(started, server, ruleStore, forwarder, events, runtimeSampler)
	httpServer := &http.Server{
		Addr:              value.ManagementListen,
		Handler:           api.NewHandler(provider, api.Config{AllowedOrigins: value.AllowedOrigins}),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	errCh := make(chan error, 4)
	go func() { errCh <- server.Serve(ctx) }()
	go func() { errCh <- forwarder.Serve(ctx) }()
	go func() {
		err := httpServer.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()
	go func() { errCh <- debug.Serve() }()
	go provider.Run(ctx, time.Second)
	logger.Info("SGW-U started", "pfcp", server.LocalAddr(), "s1u", forwarder.AccessAddr(), "s5u", forwarder.CoreAddr(), "dataplane", forwarder.Mode(), "management", value.ManagementListen, "debug", value.DebugListen)

	var runErr error
	select {
	case <-parent.Done():
	case runErr = <-errCh:
		if runErr != nil {
			cancel()
		}
	}
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	httpErr := httpServer.Shutdown(shutdownCtx)
	debugErr := debug.Shutdown(shutdownCtx)
	closeErr := errors.Join(server.Close(), forwarder.Close())
	logger.Info("SGW-U shutdown complete")
	return errors.Join(runErr, httpErr, debugErr, closeErr)
}

func fastPathNeighbours(values []config.SGWUFastPathNeighbour) ([]fastpath.Neighbour, error) {
	out := make([]fastpath.Neighbour, 0, len(values))
	for index, value := range values {
		ip, err := config.Addr(value.IP, fmt.Sprintf("fastPath.neighbours[%d].ip", index))
		if err != nil {
			return nil, err
		}
		mac, err := net.ParseMAC(value.MAC)
		if err != nil {
			return nil, fmt.Errorf("fastPath.neighbours[%d].mac: %w", index, err)
		}
		out = append(out, fastpath.Neighbour{IP: ip, MAC: append(net.HardwareAddr(nil), mac...)})
	}
	return out, nil
}
