// Package policyapi exposes a protected, idempotent policy interface for
// PGW-initiated LTE dedicated bearers. It is intended for an authoritative
// PCRF adapter or Lodestar policy controller, never for the public dashboard.
package policyapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lodestarnetworks/cups/internal/pgwc/gateway"
	"github.com/lodestarnetworks/cups/internal/pgwc/session"
	"github.com/lodestarnetworks/cups/pkg/gtpv2"
)

const (
	defaultMaxBodyBytes = int64(64 << 10)
	defaultMaxInFlight  = 64
)

type Gateway interface {
	Sessions() []session.Session
	CreateDedicatedBearer(context.Context, uint64, gateway.DedicatedBearerPlan) (session.Bearer, error)
	UpdateDedicatedBearer(context.Context, uint64, uint8, gateway.DedicatedBearerQoS) (session.Bearer, error)
	DeleteDedicatedBearer(context.Context, uint64, uint8) error
}

type Config struct {
	Token          []byte
	MaxBodyBytes   int64
	MaxInFlight    int
	RequestTimeout time.Duration
	OnEvent        func(Event)
}

type Event struct {
	Operation string
	PolicyID  string
	SessionID uint64
	Result    string
	Code      string
	Reason    string
}

type Stats struct {
	Requests     uint64
	AuthFailures uint64
	BadRequests  uint64
	Created      uint64
	Updated      uint64
	Unchanged    uint64
	Deleted      uint64
	Failed       uint64
	Saturated    uint64
	InFlight     uint64
}

type counters struct {
	requests, authFailures, badRequests  atomic.Uint64
	created, updated, unchanged, deleted atomic.Uint64
	failed, saturated, inFlight          atomic.Uint64
}

type Handler struct {
	gateway        Gateway
	tokenHash      [sha256.Size]byte
	maxBodyBytes   int64
	requestTimeout time.Duration
	onEvent        func(Event)
	slots          chan struct{}
	locks          [256]sync.Mutex
	mux            http.Handler
	counters       counters
}

type PolicyRequest struct {
	EBI                  uint8      `json:"ebi,omitempty"`
	QCI                  uint8      `json:"qci"`
	ARP                  uint8      `json:"arp"`
	PreemptionCapable    bool       `json:"preemptionCapable"`
	PreemptionVulnerable bool       `json:"preemptionVulnerable"`
	UplinkMBRBPS         uint64     `json:"uplinkMbrBps"`
	DownlinkMBRBPS       uint64     `json:"downlinkMbrBps"`
	UplinkGBRBPS         uint64     `json:"uplinkGbrBps"`
	DownlinkGBRBPS       uint64     `json:"downlinkGbrBps"`
	TFT                  TFTRequest `json:"tft"`
}

type TFTRequest struct {
	Filters []FilterRequest `json:"filters"`
}

type FilterRequest struct {
	ID            uint8        `json:"id"`
	Direction     string       `json:"direction"`
	Precedence    uint8        `json:"precedence"`
	LocalIPv4     string       `json:"localIPv4,omitempty"`
	RemoteIPv4    string       `json:"remoteIPv4,omitempty"`
	Protocol      *uint8       `json:"protocol,omitempty"`
	LocalPort     *PortRequest `json:"localPort,omitempty"`
	RemotePort    *PortRequest `json:"remotePort,omitempty"`
	TypeOfService *TOSRequest  `json:"typeOfService,omitempty"`
}

type PortRequest struct {
	From uint16 `json:"from"`
	To   uint16 `json:"to"`
}

type TOSRequest struct {
	Value uint8 `json:"value"`
	Mask  uint8 `json:"mask"`
}

type policyView struct {
	PolicyID             string  `json:"policyId"`
	EBI                  uint8   `json:"ebi"`
	QCI                  uint8   `json:"qci"`
	ARP                  uint8   `json:"arp"`
	PreemptionCapable    bool    `json:"preemptionCapable"`
	PreemptionVulnerable bool    `json:"preemptionVulnerable"`
	UplinkMBRBPS         uint64  `json:"uplinkMbrBps"`
	DownlinkMBRBPS       uint64  `json:"downlinkMbrBps"`
	UplinkGBRBPS         uint64  `json:"uplinkGbrBps"`
	DownlinkGBRBPS       uint64  `json:"downlinkGbrBps"`
	UplinkMBPS           float64 `json:"uplinkMbps"`
	DownlinkMBPS         float64 `json:"downlinkMbps"`
	TFTSHA256            string  `json:"tftSha256"`
}

type sessionView struct {
	SessionID  uint64        `json:"sessionId"`
	APN        string        `json:"apn"`
	UEIPv4     string        `json:"ueIPv4"`
	State      session.State `json:"state"`
	DefaultEBI uint8         `json:"defaultEbi"`
	Policies   []policyView  `json:"policies"`
}

func New(config Config, control Gateway) (*Handler, error) {
	if control == nil {
		return nil, errors.New("policy API requires a PGW-C gateway")
	}
	token := bytes.TrimSpace(config.Token)
	if len(token) < 32 || len(token) > 512 {
		return nil, errors.New("policy API token must contain 32..512 non-whitespace bytes")
	}
	if config.MaxBodyBytes == 0 {
		config.MaxBodyBytes = defaultMaxBodyBytes
	}
	if config.MaxBodyBytes < 1024 || config.MaxBodyBytes > 1<<20 {
		return nil, errors.New("policy API body limit must be between 1024 and 1048576 bytes")
	}
	if config.MaxInFlight == 0 {
		config.MaxInFlight = defaultMaxInFlight
	}
	if config.MaxInFlight < 1 || config.MaxInFlight > 4096 {
		return nil, errors.New("policy API maximum in-flight requests must be between 1 and 4096")
	}
	if config.RequestTimeout <= 0 || config.RequestTimeout > time.Minute {
		return nil, errors.New("policy API request timeout must be between 1ns and 1m")
	}
	handler := &Handler{
		gateway: control, tokenHash: sha256.Sum256(token), maxBodyBytes: config.MaxBodyBytes,
		requestTimeout: config.RequestTimeout, onEvent: config.OnEvent,
		slots: make(chan struct{}, config.MaxInFlight),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/healthz", handler.health)
	mux.HandleFunc("GET /v1/sessions", handler.listSessions)
	mux.HandleFunc("GET /v1/sessions/{sessionID}/policies", handler.listPolicies)
	mux.HandleFunc("GET /v1/sessions/{sessionID}/policies/{policyID}", handler.getPolicy)
	mux.HandleFunc("PUT /v1/sessions/{sessionID}/policies/{policyID}", handler.putPolicy)
	mux.HandleFunc("DELETE /v1/sessions/{sessionID}/policies/{policyID}", handler.deletePolicy)
	handler.mux = mux
	return handler, nil
}

func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	h.counters.requests.Add(1)
	secureHeaders(writer)
	if !h.authorized(request) {
		h.counters.authFailures.Add(1)
		writer.Header().Set("WWW-Authenticate", `Bearer realm="lodestar-pgw-policy"`)
		writeError(writer, http.StatusUnauthorized, "unauthorized", "valid policy credentials are required")
		return
	}
	h.mux.ServeHTTP(writer, request)
}

func (h *Handler) Stats() Stats {
	return Stats{
		Requests: h.counters.requests.Load(), AuthFailures: h.counters.authFailures.Load(),
		BadRequests: h.counters.badRequests.Load(), Created: h.counters.created.Load(),
		Updated: h.counters.updated.Load(), Unchanged: h.counters.unchanged.Load(),
		Deleted: h.counters.deleted.Load(), Failed: h.counters.failed.Load(),
		Saturated: h.counters.saturated.Load(), InFlight: h.counters.inFlight.Load(),
	}
}

func (h *Handler) authorized(request *http.Request) bool {
	const prefix = "Bearer "
	value := request.Header.Get("Authorization")
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	presented := sha256.Sum256([]byte(strings.TrimSpace(strings.TrimPrefix(value, prefix))))
	return subtle.ConstantTimeCompare(presented[:], h.tokenHash[:]) == 1
}

func (h *Handler) health(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]any{"status": "ready", "sessions": len(h.gateway.Sessions())})
}

func (h *Handler) listSessions(writer http.ResponseWriter, request *http.Request) {
	ueFilter := strings.TrimSpace(request.URL.Query().Get("ue_ipv4"))
	apnFilter := strings.ToLower(strings.TrimSpace(request.URL.Query().Get("apn")))
	if ueFilter != "" {
		address, err := netip.ParseAddr(ueFilter)
		if err != nil || !address.Is4() {
			h.badRequest(writer, "invalid_query", "ue_ipv4 must be an IPv4 address")
			return
		}
		ueFilter = address.Unmap().String()
	}
	views := make([]sessionView, 0)
	for _, current := range h.gateway.Sessions() {
		if ueFilter != "" && current.UEIPv4.String() != ueFilter || apnFilter != "" && strings.ToLower(current.APN) != apnFilter {
			continue
		}
		views = append(views, viewSession(current))
	}
	sort.Slice(views, func(left, right int) bool { return views[left].SessionID < views[right].SessionID })
	writeJSON(writer, http.StatusOK, map[string]any{"sessions": views})
}

func (h *Handler) listPolicies(writer http.ResponseWriter, request *http.Request) {
	current, ok := h.requestSession(writer, request)
	if !ok {
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"session": viewSession(current)})
}

func (h *Handler) getPolicy(writer http.ResponseWriter, request *http.Request) {
	current, ok := h.requestSession(writer, request)
	if !ok {
		return
	}
	policyID, ok := h.requestPolicyID(writer, request)
	if !ok {
		return
	}
	bearer, found := findPolicy(current, policyID)
	if !found {
		writeError(writer, http.StatusNotFound, "policy_not_found", "policy does not exist on this session")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"policy": viewPolicy(bearer)})
}

func (h *Handler) putPolicy(writer http.ResponseWriter, request *http.Request) {
	sessionID, ok := h.requestSessionID(writer, request)
	if !ok {
		return
	}
	policyID, ok := h.requestPolicyID(writer, request)
	if !ok {
		return
	}
	var desired PolicyRequest
	if err := decodeStrict(writer, request, h.maxBodyBytes, &desired); err != nil {
		h.badRequest(writer, "invalid_request", err.Error())
		return
	}
	tft, rawTFT, err := buildTFT(desired.TFT)
	if err != nil {
		h.badRequest(writer, "invalid_tft", err.Error())
		return
	}
	qos := gateway.DedicatedBearerQoS{
		QCI: desired.QCI, ARP: desired.ARP,
		PreemptionCapable: desired.PreemptionCapable, PreemptionVulnerable: desired.PreemptionVulnerable,
		UplinkMBR: desired.UplinkMBRBPS, DownlinkMBR: desired.DownlinkMBRBPS,
		UplinkGBR: desired.UplinkGBRBPS, DownlinkGBR: desired.DownlinkGBRBPS,
	}
	if err := validateQoS(qos); err != nil {
		h.badRequest(writer, "invalid_qos", err.Error())
		return
	}
	if !h.acquire(writer) {
		return
	}
	defer h.release()
	lock := &h.locks[byte(sessionID)]
	lock.Lock()
	defer lock.Unlock()
	ctx, cancel := context.WithTimeout(request.Context(), h.requestTimeout)
	defer cancel()
	current, found := findSession(h.gateway.Sessions(), sessionID)
	if !found {
		writeError(writer, http.StatusNotFound, "session_not_found", "PGW-C session does not exist")
		return
	}
	if installed, exists := findPolicy(current, policyID); exists {
		if desired.EBI != 0 && desired.EBI != installed.EBI {
			h.conflict(writer, "ebi_conflict", "policy already owns a different EBI")
			return
		}
		if !bytes.Equal(installed.TFT, rawTFT) {
			h.conflict(writer, "tft_change_requires_replace", "delete and recreate the policy to change its TFT")
			return
		}
		if sameQoS(installed, qos) {
			h.counters.unchanged.Add(1)
			h.emit(Event{Operation: "put", PolicyID: policyID, SessionID: sessionID, Result: "unchanged"})
			writeJSON(writer, http.StatusOK, map[string]any{"result": "unchanged", "policy": viewPolicy(installed)})
			return
		}
		updated, err := h.gateway.UpdateDedicatedBearer(ctx, sessionID, installed.EBI, qos)
		if err != nil {
			h.operationError(writer, "update", policyID, sessionID, err)
			return
		}
		h.counters.updated.Add(1)
		h.emit(Event{Operation: "update", PolicyID: policyID, SessionID: sessionID, Result: "accepted"})
		writeJSON(writer, http.StatusOK, map[string]any{"result": "updated", "policy": viewPolicy(updated)})
		return
	}
	created, err := h.gateway.CreateDedicatedBearer(ctx, sessionID, gateway.DedicatedBearerPlan{
		PolicyID: policyID, EBI: desired.EBI, QCI: qos.QCI, ARP: qos.ARP,
		PreemptionCapable: qos.PreemptionCapable, PreemptionVulnerable: qos.PreemptionVulnerable,
		UplinkMBR: qos.UplinkMBR, DownlinkMBR: qos.DownlinkMBR, UplinkGBR: qos.UplinkGBR, DownlinkGBR: qos.DownlinkGBR,
		TFT: tft,
	})
	if err != nil {
		h.operationError(writer, "create", policyID, sessionID, err)
		return
	}
	h.counters.created.Add(1)
	h.emit(Event{Operation: "create", PolicyID: policyID, SessionID: sessionID, Result: "accepted"})
	writeJSON(writer, http.StatusCreated, map[string]any{"result": "created", "policy": viewPolicy(created)})
}

func (h *Handler) deletePolicy(writer http.ResponseWriter, request *http.Request) {
	sessionID, ok := h.requestSessionID(writer, request)
	if !ok {
		return
	}
	policyID, ok := h.requestPolicyID(writer, request)
	if !ok {
		return
	}
	if !h.acquire(writer) {
		return
	}
	defer h.release()
	lock := &h.locks[byte(sessionID)]
	lock.Lock()
	defer lock.Unlock()
	current, found := findSession(h.gateway.Sessions(), sessionID)
	if !found {
		writeError(writer, http.StatusNotFound, "session_not_found", "PGW-C session does not exist")
		return
	}
	bearer, exists := findPolicy(current, policyID)
	if !exists {
		h.counters.unchanged.Add(1)
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), h.requestTimeout)
	defer cancel()
	if err := h.gateway.DeleteDedicatedBearer(ctx, sessionID, bearer.EBI); err != nil {
		h.operationError(writer, "delete", policyID, sessionID, err)
		return
	}
	h.counters.deleted.Add(1)
	h.emit(Event{Operation: "delete", PolicyID: policyID, SessionID: sessionID, Result: "accepted"})
	writer.WriteHeader(http.StatusNoContent)
}

func (h *Handler) acquire(writer http.ResponseWriter) bool {
	select {
	case h.slots <- struct{}{}:
		h.counters.inFlight.Add(1)
		return true
	default:
		h.counters.saturated.Add(1)
		writeError(writer, http.StatusServiceUnavailable, "policy_api_saturated", "policy operation capacity is temporarily exhausted")
		return false
	}
}

func (h *Handler) release() {
	<-h.slots
	h.counters.inFlight.Add(^uint64(0))
}

func (h *Handler) requestSession(writer http.ResponseWriter, request *http.Request) (session.Session, bool) {
	sessionID, ok := h.requestSessionID(writer, request)
	if !ok {
		return session.Session{}, false
	}
	current, found := findSession(h.gateway.Sessions(), sessionID)
	if !found {
		writeError(writer, http.StatusNotFound, "session_not_found", "PGW-C session does not exist")
		return session.Session{}, false
	}
	return current, true
}

func (h *Handler) requestSessionID(writer http.ResponseWriter, request *http.Request) (uint64, bool) {
	value, err := strconv.ParseUint(request.PathValue("sessionID"), 10, 64)
	if err != nil || value == 0 {
		h.badRequest(writer, "invalid_session_id", "session ID must be a positive integer")
		return 0, false
	}
	return value, true
}

func (h *Handler) requestPolicyID(writer http.ResponseWriter, request *http.Request) (string, bool) {
	value := request.PathValue("policyID")
	if !session.ValidPolicyID(value) {
		h.badRequest(writer, "invalid_policy_id", "policy ID must be 1..64 URL-safe characters and begin with an alphanumeric character")
		return "", false
	}
	return value, true
}

func (h *Handler) badRequest(writer http.ResponseWriter, code, message string) {
	h.counters.badRequests.Add(1)
	writeError(writer, http.StatusBadRequest, code, message)
}

func (h *Handler) conflict(writer http.ResponseWriter, code, message string) {
	h.counters.failed.Add(1)
	writeError(writer, http.StatusConflict, code, message)
}

func (h *Handler) operationError(writer http.ResponseWriter, operation, policyID string, sessionID uint64, err error) {
	h.counters.failed.Add(1)
	status := http.StatusBadGateway
	code := "bearer_procedure_failed"
	message := "an LTE control-plane peer rejected or failed the bearer procedure"
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		status, code, message = http.StatusGatewayTimeout, "policy_operation_timeout", "the LTE bearer procedure did not complete before its deadline"
	case errors.Is(err, gateway.ErrSessionNotFound):
		status, code, message = http.StatusNotFound, "session_not_found", "PGW-C session does not exist"
	case errors.Is(err, gateway.ErrBearerNotFound):
		status, code, message = http.StatusNotFound, "policy_not_found", "dedicated bearer no longer exists"
	case errors.Is(err, gateway.ErrBearerRejected), errors.Is(err, session.ErrConflict), errors.Is(err, session.ErrInvalidSession):
		status, code, message = http.StatusConflict, "policy_rejected", "the requested policy conflicts with current LTE session state"
	}
	h.emit(Event{
		Operation: operation, PolicyID: policyID, SessionID: sessionID,
		Result: "rejected", Code: code, Reason: auditReason(err),
	})
	writeError(writer, status, code, message)
}

func auditReason(err error) string {
	reason := strings.Join(strings.Fields(err.Error()), " ")
	if len(reason) > 512 {
		reason = reason[:512]
	}
	return reason
}

func (h *Handler) emit(event Event) {
	if h.onEvent != nil {
		h.onEvent(event)
	}
}

func findSession(sessions []session.Session, id uint64) (session.Session, bool) {
	for _, current := range sessions {
		if current.ID == id {
			return current, true
		}
	}
	return session.Session{}, false
}

func findPolicy(current session.Session, policyID string) (session.Bearer, bool) {
	for _, bearer := range current.DedicatedBearers {
		if bearer.PolicyID == policyID {
			return bearer, true
		}
	}
	return session.Bearer{}, false
}

func viewSession(current session.Session) sessionView {
	policies := make([]policyView, 0, len(current.DedicatedBearers))
	for _, bearer := range current.DedicatedBearers {
		if bearer.PolicyID != "" {
			policies = append(policies, viewPolicy(bearer))
		}
	}
	sort.Slice(policies, func(left, right int) bool { return policies[left].PolicyID < policies[right].PolicyID })
	return sessionView{
		SessionID: current.ID, APN: current.APN, UEIPv4: current.UEIPv4.String(),
		State: current.State, DefaultEBI: current.EBI, Policies: policies,
	}
}

func viewPolicy(bearer session.Bearer) policyView {
	digest := sha256.Sum256(bearer.TFT)
	return policyView{
		PolicyID: bearer.PolicyID, EBI: bearer.EBI, QCI: bearer.QCI, ARP: bearer.ARP,
		PreemptionCapable: bearer.PreemptionCapable, PreemptionVulnerable: bearer.PreemptionVulnerable,
		UplinkMBRBPS: bearer.UplinkMBR, DownlinkMBRBPS: bearer.DownlinkMBR,
		UplinkGBRBPS: bearer.UplinkGBR, DownlinkGBRBPS: bearer.DownlinkGBR,
		UplinkMBPS: float64(bearer.UplinkMBR) / 1_000_000, DownlinkMBPS: float64(bearer.DownlinkMBR) / 1_000_000,
		TFTSHA256: hex.EncodeToString(digest[:]),
	}
}

func sameQoS(bearer session.Bearer, desired gateway.DedicatedBearerQoS) bool {
	return bearer.QCI == desired.QCI && bearer.ARP == desired.ARP &&
		bearer.PreemptionCapable == desired.PreemptionCapable && bearer.PreemptionVulnerable == desired.PreemptionVulnerable &&
		bearer.UplinkMBR == desired.UplinkMBR && bearer.DownlinkMBR == desired.DownlinkMBR &&
		bearer.UplinkGBR == desired.UplinkGBR && bearer.DownlinkGBR == desired.DownlinkGBR
}

func validateQoS(qos gateway.DedicatedBearerQoS) error {
	if qos.QCI == 0 || qos.QCI == 255 || qos.ARP == 0 || qos.ARP > 15 {
		return errors.New("qci must be 1..254 and arp must be 1..15")
	}
	const maxBitrate = uint64(^uint32(0)) * 1000
	for _, value := range []uint64{qos.UplinkMBR, qos.DownlinkMBR, qos.UplinkGBR, qos.DownlinkGBR} {
		if value%1000 != 0 || value > maxBitrate {
			return errors.New("all bitrates must be whole kbps within the LTE/PFCP range")
		}
	}
	if qos.UplinkGBR > qos.UplinkMBR || qos.DownlinkGBR > qos.DownlinkMBR {
		return errors.New("GBR cannot exceed MBR")
	}
	return nil
}

func buildTFT(request TFTRequest) (gtpv2.TrafficFlowTemplate, []byte, error) {
	if len(request.Filters) == 0 || len(request.Filters) > 15 {
		return gtpv2.TrafficFlowTemplate{}, nil, errors.New("tft requires 1..15 packet filters")
	}
	filters := make([]gtpv2.PacketFilter, 0, len(request.Filters))
	for index, requested := range request.Filters {
		direction, err := parseDirection(requested.Direction)
		if err != nil {
			return gtpv2.TrafficFlowTemplate{}, nil, fmt.Errorf("filter %d: %w", index, err)
		}
		components := make([]gtpv2.PacketFilterComponent, 0, 6)
		if requested.RemoteIPv4 != "" {
			value, err := prefixComponent(requested.RemoteIPv4)
			if err != nil {
				return gtpv2.TrafficFlowTemplate{}, nil, fmt.Errorf("filter %d remoteIPv4: %w", index, err)
			}
			components = append(components, gtpv2.PacketFilterComponent{Type: gtpv2.TFTComponentIPv4RemoteAddress, Value: value})
		}
		if requested.LocalIPv4 != "" {
			value, err := prefixComponent(requested.LocalIPv4)
			if err != nil {
				return gtpv2.TrafficFlowTemplate{}, nil, fmt.Errorf("filter %d localIPv4: %w", index, err)
			}
			components = append(components, gtpv2.PacketFilterComponent{Type: gtpv2.TFTComponentIPv4LocalAddress, Value: value})
		}
		if requested.Protocol != nil {
			components = append(components, gtpv2.PacketFilterComponent{Type: gtpv2.TFTComponentProtocol, Value: []byte{*requested.Protocol}})
		}
		if (requested.LocalPort != nil || requested.RemotePort != nil) && (requested.Protocol == nil || *requested.Protocol != 6 && *requested.Protocol != 17 && *requested.Protocol != 132) {
			return gtpv2.TrafficFlowTemplate{}, nil, fmt.Errorf("filter %d: TCP, UDP, or SCTP protocol is required when ports are present", index)
		}
		if requested.LocalPort != nil {
			component, err := portComponent(*requested.LocalPort, gtpv2.TFTComponentSingleLocalPort, gtpv2.TFTComponentLocalPortRange)
			if err != nil {
				return gtpv2.TrafficFlowTemplate{}, nil, fmt.Errorf("filter %d localPort: %w", index, err)
			}
			components = append(components, component)
		}
		if requested.RemotePort != nil {
			component, err := portComponent(*requested.RemotePort, gtpv2.TFTComponentSingleRemotePort, gtpv2.TFTComponentRemotePortRange)
			if err != nil {
				return gtpv2.TrafficFlowTemplate{}, nil, fmt.Errorf("filter %d remotePort: %w", index, err)
			}
			components = append(components, component)
		}
		if requested.TypeOfService != nil {
			if requested.TypeOfService.Mask == 0 {
				return gtpv2.TrafficFlowTemplate{}, nil, fmt.Errorf("filter %d: typeOfService mask cannot be zero", index)
			}
			components = append(components, gtpv2.PacketFilterComponent{Type: gtpv2.TFTComponentTypeOfService, Value: []byte{requested.TypeOfService.Value, requested.TypeOfService.Mask}})
		}
		if len(components) == 0 {
			return gtpv2.TrafficFlowTemplate{}, nil, fmt.Errorf("filter %d contains no classifier components", index)
		}
		filters = append(filters, gtpv2.PacketFilter{ID: requested.ID, Direction: direction, Precedence: requested.Precedence, Components: components})
	}
	tft := gtpv2.TrafficFlowTemplate{Operation: gtpv2.TFTOperationCreate, Filters: filters}
	raw, err := gtpv2.MarshalBearerTFT(tft)
	if err != nil {
		return gtpv2.TrafficFlowTemplate{}, nil, err
	}
	canonical, err := gtpv2.ParseBearerTFT(raw)
	if err != nil {
		return gtpv2.TrafficFlowTemplate{}, nil, err
	}
	uplink, downlink := false, false
	for _, filter := range canonical.Filters {
		uplink = uplink || filter.Direction == gtpv2.TFTDirectionUplink || filter.Direction == gtpv2.TFTDirectionBidirectional
		downlink = downlink || filter.Direction == gtpv2.TFTDirectionDownlink || filter.Direction == gtpv2.TFTDirectionBidirectional
	}
	if !uplink || !downlink {
		return gtpv2.TrafficFlowTemplate{}, nil, errors.New("tft must classify both uplink and downlink traffic")
	}
	return canonical, raw, nil
}

func parseDirection(value string) (gtpv2.TFTDirection, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "uplink":
		return gtpv2.TFTDirectionUplink, nil
	case "downlink":
		return gtpv2.TFTDirectionDownlink, nil
	case "bidirectional":
		return gtpv2.TFTDirectionBidirectional, nil
	default:
		return 0, errors.New("direction must be uplink, downlink, or bidirectional")
	}
}

func prefixComponent(value string) ([]byte, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
	if err != nil || !prefix.Addr().Is4() {
		return nil, errors.New("value must be an IPv4 prefix")
	}
	prefix = prefix.Masked()
	address := prefix.Addr().As4()
	bits := prefix.Bits()
	mask := uint32(0)
	if bits != 0 {
		mask = ^uint32(0) << (32 - bits)
	}
	out := make([]byte, 8)
	copy(out[:4], address[:])
	binary.BigEndian.PutUint32(out[4:], mask)
	return out, nil
}

func portComponent(port PortRequest, singleType, rangeType uint8) (gtpv2.PacketFilterComponent, error) {
	if port.From > port.To {
		return gtpv2.PacketFilterComponent{}, errors.New("from cannot exceed to")
	}
	if port.From == port.To {
		value := make([]byte, 2)
		binary.BigEndian.PutUint16(value, port.From)
		return gtpv2.PacketFilterComponent{Type: singleType, Value: value}, nil
	}
	value := make([]byte, 4)
	binary.BigEndian.PutUint16(value[:2], port.From)
	binary.BigEndian.PutUint16(value[2:], port.To)
	return gtpv2.PacketFilterComponent{Type: rangeType, Value: value}, nil
}

func decodeStrict(writer http.ResponseWriter, request *http.Request, limit int64, destination any) error {
	request.Body = http.MaxBytesReader(writer, request.Body, limit)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode JSON body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("request body contains a trailing JSON value")
	}
	return nil
}

func secureHeaders(writer http.ResponseWriter) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("X-Frame-Options", "DENY")
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeError(writer http.ResponseWriter, status int, code, message string) {
	writeJSON(writer, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}
