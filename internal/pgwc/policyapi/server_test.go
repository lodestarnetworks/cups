package policyapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/lodestarnetworks/cups/internal/pgwc/gateway"
	"github.com/lodestarnetworks/cups/internal/pgwc/session"
	"github.com/lodestarnetworks/cups/pkg/gtpv2"
)

var testToken = []byte("0123456789abcdef0123456789abcdef")

type fakeGateway struct {
	mu                        sync.Mutex
	session                   session.Session
	creates, updates, deletes int
	createErr                 error
}

func newFakeGateway() *fakeGateway {
	return &fakeGateway{session: session.Session{
		ID: 42, Revision: 1, APN: "ims", State: session.StateActive, EBI: 5,
		UEIPv4: netip.MustParseAddr("10.46.0.2"), DedicatedBearers: make(map[uint8]session.Bearer),
	}}
}

func (f *fakeGateway) Sessions() []session.Session {
	f.mu.Lock()
	defer f.mu.Unlock()
	current := f.session
	current.DedicatedBearers = make(map[uint8]session.Bearer, len(f.session.DedicatedBearers))
	for ebi, bearer := range f.session.DedicatedBearers {
		bearer.TFT = append([]byte(nil), bearer.TFT...)
		current.DedicatedBearers[ebi] = bearer
	}
	return []session.Session{current}
}

func (f *fakeGateway) CreateDedicatedBearer(_ context.Context, sessionID uint64, plan gateway.DedicatedBearerPlan) (session.Bearer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return session.Bearer{}, f.createErr
	}
	raw, err := gtpv2.MarshalBearerTFT(plan.TFT)
	if err != nil {
		return session.Bearer{}, err
	}
	ebi := plan.EBI
	if ebi == 0 {
		ebi = 6
	}
	bearer := session.Bearer{
		PolicyID: plan.PolicyID, EBI: ebi, QCI: plan.QCI, ARP: plan.ARP,
		PreemptionCapable: plan.PreemptionCapable, PreemptionVulnerable: plan.PreemptionVulnerable,
		UplinkMBR: plan.UplinkMBR, DownlinkMBR: plan.DownlinkMBR,
		UplinkGBR: plan.UplinkGBR, DownlinkGBR: plan.DownlinkGBR, TFT: raw,
	}
	f.session.DedicatedBearers[ebi] = bearer
	f.creates++
	return bearer, nil
}

func TestPolicyFailureResponseIsSanitizedAndAuditRetainsReason(t *testing.T) {
	control := newFakeGateway()
	control.createErr = errors.New("S5-C transaction failed for internal peer")
	var events []Event
	handler, err := New(Config{
		Token: testToken, RequestTimeout: time.Second,
		OnEvent: func(event Event) { events = append(events, event) },
	}, control)
	if err != nil {
		t.Fatal(err)
	}
	response := request(handler, http.MethodPut, "/v1/sessions/42/policies/audit-test", validPolicyRequest(), true)
	if response.Code != http.StatusBadGateway || bytes.Contains(response.Body.Bytes(), []byte("internal peer")) {
		t.Fatalf("sanitized failure = %d, body=%s", response.Code, response.Body.String())
	}
	if len(events) != 1 || events[0].Code != "bearer_procedure_failed" || events[0].Reason != control.createErr.Error() {
		t.Fatalf("audit event = %#v", events)
	}
}

func (f *fakeGateway) UpdateDedicatedBearer(_ context.Context, _ uint64, ebi uint8, qos gateway.DedicatedBearerQoS) (session.Bearer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	bearer := f.session.DedicatedBearers[ebi]
	bearer.QCI, bearer.ARP = qos.QCI, qos.ARP
	bearer.PreemptionCapable, bearer.PreemptionVulnerable = qos.PreemptionCapable, qos.PreemptionVulnerable
	bearer.UplinkMBR, bearer.DownlinkMBR = qos.UplinkMBR, qos.DownlinkMBR
	bearer.UplinkGBR, bearer.DownlinkGBR = qos.UplinkGBR, qos.DownlinkGBR
	f.session.DedicatedBearers[ebi] = bearer
	f.updates++
	return bearer, nil
}

func (f *fakeGateway) DeleteDedicatedBearer(_ context.Context, _ uint64, ebi uint8) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.session.DedicatedBearers, ebi)
	f.deletes++
	return nil
}

func TestPolicyLifecycleIsAuthenticatedStrictAndIdempotent(t *testing.T) {
	control := newFakeGateway()
	handler, err := New(Config{Token: testToken, RequestTimeout: time.Second}, control)
	if err != nil {
		t.Fatal(err)
	}

	unauthorized := request(handler, http.MethodGet, "/v1/sessions", nil, false)
	if unauthorized.Code != http.StatusUnauthorized || unauthorized.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("unauthorized response = %d, headers=%v", unauthorized.Code, unauthorized.Header())
	}
	invalid := validPolicyRequest()
	invalid["unknown"] = true
	bad := request(handler, http.MethodPut, "/v1/sessions/42/policies/ims-voice", invalid, true)
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("strict request status = %d, body=%s", bad.Code, bad.Body.String())
	}

	created := request(handler, http.MethodPut, "/v1/sessions/42/policies/ims-voice", validPolicyRequest(), true)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body=%s", created.Code, created.Body.String())
	}
	replayed := request(handler, http.MethodPut, "/v1/sessions/42/policies/ims-voice", validPolicyRequest(), true)
	if replayed.Code != http.StatusOK || !bytes.Contains(replayed.Body.Bytes(), []byte(`"unchanged"`)) {
		t.Fatalf("idempotent replay = %d, body=%s", replayed.Code, replayed.Body.String())
	}

	updatedRequest := validPolicyRequest()
	updatedRequest["uplinkMbrBps"] = uint64(9_000_000)
	updated := request(handler, http.MethodPut, "/v1/sessions/42/policies/ims-voice", updatedRequest, true)
	if updated.Code != http.StatusOK || !bytes.Contains(updated.Body.Bytes(), []byte(`"updated"`)) {
		t.Fatalf("update = %d, body=%s", updated.Code, updated.Body.String())
	}

	tftChanged := validPolicyRequest()
	filters := tftChanged["tft"].(map[string]any)["filters"].([]map[string]any)
	filters[0]["remotePort"] = map[string]uint16{"from": 6000, "to": 6000}
	conflict := request(handler, http.MethodPut, "/v1/sessions/42/policies/ims-voice", tftChanged, true)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("TFT replacement = %d, body=%s", conflict.Code, conflict.Body.String())
	}

	listed := request(handler, http.MethodGet, "/v1/sessions?ue_ipv4=10.46.0.2&apn=IMS", nil, true)
	if listed.Code != http.StatusOK || !bytes.Contains(listed.Body.Bytes(), []byte(`"uplinkMbps":9`)) {
		t.Fatalf("session list = %d, body=%s", listed.Code, listed.Body.String())
	}
	deleted := request(handler, http.MethodDelete, "/v1/sessions/42/policies/ims-voice", nil, true)
	deletedAgain := request(handler, http.MethodDelete, "/v1/sessions/42/policies/ims-voice", nil, true)
	if deleted.Code != http.StatusNoContent || deletedAgain.Code != http.StatusNoContent {
		t.Fatalf("delete statuses = %d, %d", deleted.Code, deletedAgain.Code)
	}

	control.mu.Lock()
	creates, updates, deletes := control.creates, control.updates, control.deletes
	control.mu.Unlock()
	if creates != 1 || updates != 1 || deletes != 1 {
		t.Fatalf("gateway calls create=%d update=%d delete=%d", creates, updates, deletes)
	}
	stats := handler.Stats()
	if stats.AuthFailures != 1 || stats.BadRequests != 1 || stats.Created != 1 || stats.Updated != 1 || stats.Deleted != 1 || stats.Unchanged != 2 || stats.InFlight != 0 {
		t.Fatalf("policy API stats = %#v", stats)
	}
}

func TestConcurrentPolicyPutCreatesExactlyOnce(t *testing.T) {
	control := newFakeGateway()
	handler, err := New(Config{Token: testToken, RequestTimeout: time.Second}, control)
	if err != nil {
		t.Fatal(err)
	}
	const workers = 16
	statuses := make(chan int, workers)
	var group sync.WaitGroup
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			statuses <- request(handler, http.MethodPut, "/v1/sessions/42/policies/ims-media", validPolicyRequest(), true).Code
		}()
	}
	group.Wait()
	close(statuses)
	created, unchanged := 0, 0
	for status := range statuses {
		switch status {
		case http.StatusCreated:
			created++
		case http.StatusOK:
			unchanged++
		default:
			t.Fatalf("unexpected concurrent status %d", status)
		}
	}
	control.mu.Lock()
	creates := control.creates
	control.mu.Unlock()
	if created != 1 || unchanged != workers-1 || creates != 1 {
		t.Fatalf("created=%d unchanged=%d gateway_creates=%d", created, unchanged, creates)
	}
}

func TestTFTValidationRejectsUnsafeOrOneWayFilters(t *testing.T) {
	control := newFakeGateway()
	handler, _ := New(Config{Token: testToken, RequestTimeout: time.Second}, control)
	oneWay := validPolicyRequest()
	filters := oneWay["tft"].(map[string]any)["filters"].([]map[string]any)
	filters[0]["direction"] = "uplink"
	response := request(handler, http.MethodPut, "/v1/sessions/42/policies/one-way", oneWay, true)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("one-way TFT status=%d body=%s", response.Code, response.Body.String())
	}
	unsafePorts := validPolicyRequest()
	unsafeFilters := unsafePorts["tft"].(map[string]any)["filters"].([]map[string]any)
	unsafeFilters[0]["protocol"] = uint8(1)
	response = request(handler, http.MethodPut, "/v1/sessions/42/policies/unsafe", unsafePorts, true)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unsafe port TFT status=%d body=%s", response.Code, response.Body.String())
	}
}

func request(handler http.Handler, method, target string, body any, authenticate bool) *httptest.ResponseRecorder {
	var encoded []byte
	if body != nil {
		encoded, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, target, bytes.NewReader(encoded))
	if authenticate {
		req.Header.Set("Authorization", "Bearer "+string(testToken))
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}

func validPolicyRequest() map[string]any {
	return map[string]any{
		"ebi": uint8(6), "qci": uint8(1), "arp": uint8(2),
		"preemptionCapable": true, "preemptionVulnerable": false,
		"uplinkMbrBps": uint64(8_000_000), "downlinkMbrBps": uint64(12_000_000),
		"uplinkGbrBps": uint64(3_000_000), "downlinkGbrBps": uint64(4_000_000),
		"tft": map[string]any{"filters": []map[string]any{{
			"id": uint8(1), "direction": "bidirectional", "precedence": uint8(10), "protocol": uint8(17),
			"localPort":  map[string]uint16{"from": 5004, "to": 5004},
			"remotePort": map[string]uint16{"from": 5005, "to": 5005},
		}}},
	}
}
