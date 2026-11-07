package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// setupHandlerTest points the package's db at an in-memory sqlite instance
// with the production schema, so handler tests exercise real queries.
func setupHandlerTest(t *testing.T) {
	t.Helper()
	withTestKey(t)

	original := db
	tdb, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	for _, model := range []any{&Device{}, &Signer{}, &Account{}, &MigratedAccountData{}} {
		if err := tdb.AutoMigrate(model); err != nil {
			t.Fatalf("failed to migrate %T: %v", model, err)
		}
	}
	db = tdb
	t.Cleanup(func() { db = original })
}

func asUser(r *http.Request, userId, provider string) *http.Request {
	ctx := context.WithValue(r.Context(), fieldUserId, userId)
	ctx = context.WithValue(ctx, fieldAuthProvider, provider)
	return r.WithContext(ctx)
}

func seedAccount(t *testing.T, userId, provider, address string) (Account, Device) {
	t.Helper()
	signer := Signer{ID: uuid.NewString()}
	if err := db.Create(&signer).Error; err != nil {
		t.Fatalf("seed signer: %v", err)
	}
	device, err := newDevice("share-of-"+userId, signer.ID, true)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	if err := db.Create(&device).Error; err != nil {
		t.Fatalf("seed device row: %v", err)
	}
	account := Account{
		ID:           uuid.NewString(),
		Address:      address,
		Username:     userId,
		ChainId:      80002,
		AuthProvider: provider,
		SignerId:     signer.ID,
	}
	if err := db.Create(&account).Error; err != nil {
		t.Fatalf("seed account: %v", err)
	}
	return account, device
}

// Every query must filter on both the authenticated username and the auth
// provider; dropping either predicate is an IDOR. These tests pin that.
func TestGetDeviceIsScopedToOwner(t *testing.T) {
	setupHandlerTest(t)
	_, aliceDevice := seedAccount(t, "alice", "default", "0xaaa1")
	_, bobDevice := seedAccount(t, "bob", "default", "0xbbb1")

	h := apiMux()

	w := httptest.NewRecorder()
	h.ServeHTTP(w, asUser(httptest.NewRequest(http.MethodGet, "/v1/devices/"+bobDevice.ID, nil), "alice", "default"))
	if w.Code != http.StatusNotFound {
		t.Fatalf("alice fetching bob's device got %d, want 404", w.Code)
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, asUser(httptest.NewRequest(http.MethodGet, "/v1/devices/"+aliceDevice.ID, nil), "alice", "default"))
	if w.Code != http.StatusOK {
		t.Fatalf("alice fetching her own device got %d, want 200", w.Code)
	}
	var resp DeviceResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Share != "share-of-alice" {
		t.Fatalf("got share %q, want the decrypted seeded share", resp.Share)
	}
}

func TestListAccountsIsScopedToUserAndProvider(t *testing.T) {
	setupHandlerTest(t)
	seedAccount(t, "alice", "default", "0xaaa2")
	seedAccount(t, "bob", "default", "0xbbb2")
	// Same username under a different provider is a different subject.
	seedAccount(t, "alice", "google", "0xccc2")

	w := httptest.NewRecorder()
	apiMux().ServeHTTP(w, asUser(httptest.NewRequest(http.MethodGet, "/v2/accounts", nil), "alice", "default"))
	if w.Code != http.StatusOK {
		t.Fatalf("list accounts got %d, want 200", w.Code)
	}
	var resp AccountListResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Total != 1 || resp.Data[0].Address != "0xaaa2" {
		t.Fatalf("alice@default sees %d account(s) %v, want only her own", resp.Total, resp.Data)
	}
}

func TestImportShareConflicts(t *testing.T) {
	setupHandlerTest(t)
	account, _ := seedAccount(t, "bob", "default", "0xheld")

	importReq := func() *http.Request {
		body := `{"address":"0xheld","share":"some-share","chainId":80002,"userId":"former-alice"}`
		r := httptest.NewRequest(http.MethodPost, "/v2/accounts/import-share", strings.NewReader(body))
		return asUser(r, "alice", "default")
	}

	w := httptest.NewRecorder()
	apiMux().ServeHTTP(w, importReq())
	if w.Code != http.StatusConflict {
		t.Fatalf("import to a held address got %d, want 409", w.Code)
	}

	// A soft-deleted holder still owns the row under the unique index, so it
	// must be reported as the same conflict, not an internal error.
	if err := db.Delete(&account).Error; err != nil {
		t.Fatalf("soft-delete account: %v", err)
	}
	w = httptest.NewRecorder()
	apiMux().ServeHTTP(w, importReq())
	if w.Code != http.StatusConflict {
		t.Fatalf("import to a soft-deleted address got %d, want 409", w.Code)
	}
}

func TestImportShareRequiresUserId(t *testing.T) {
	setupHandlerTest(t)
	body := `{"address":"0xnew","share":"some-share","chainId":80002}`
	r := httptest.NewRequest(http.MethodPost, "/v2/accounts/import-share", strings.NewReader(body))
	w := httptest.NewRecorder()
	apiMux().ServeHTTP(w, asUser(r, "alice", "default"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("import without userId got %d, want 400", w.Code)
	}
	var n int64
	db.Unscoped().Model(&Account{}).Where("address = ?", "0xnew").Count(&n)
	if n != 0 {
		t.Fatalf("import without userId persisted %d account row(s), want 0", n)
	}
}

// The unique index on address is global, so the pre-check must be too: a
// holder under another provider is a 409, not an index violation reported as 500.
func TestCreateDeviceV2ConflictsAcrossProviders(t *testing.T) {
	setupHandlerTest(t)
	seedAccount(t, "bob", "google", "0xheld")

	body := `{"address":"0xheld","share":"some-share","chainId":80002}`
	r := httptest.NewRequest(http.MethodPost, "/v2/devices/create", strings.NewReader(body))
	w := httptest.NewRecorder()
	apiMux().ServeHTTP(w, asUser(r, "alice", "default"))
	if w.Code != http.StatusConflict {
		t.Fatalf("create on an address held under another provider got %d, want 409", w.Code)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	setupHandlerTest(t)
	w := httptest.NewRecorder()
	apiMux().ServeHTTP(w, asUser(httptest.NewRequest(http.MethodGet, "/v2/devices/create", nil), "alice", "default"))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET on create got %d, want 405", w.Code)
	}
}

func TestBareDevicesPathRoutesToList(t *testing.T) {
	setupHandlerTest(t)
	seedAccount(t, "alice", "default", "0xaaa3")

	w := httptest.NewRecorder()
	apiMux().ServeHTTP(w, asUser(httptest.NewRequest(http.MethodGet, "/v1/devices", nil), "alice", "default"))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /v1/devices got %d, want the device list", w.Code)
	}
	var resp DeviceListResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Total != 1 {
		t.Fatalf("got %d devices, want 1", resp.Total)
	}
}

// The composed chain must authenticate before it rate-limits: a flood of
// unauthenticated requests yields 401s, never a 429, because the limiter has
// no verified subject to charge.
func TestUnauthenticatedRequestsAreRejectedNotThrottled(t *testing.T) {
	setupHandlerTest(t)
	h := buildHandler()

	for i := 0; i < rateLimitBurst+10; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v2/accounts", nil))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("request %d got %d, want 401", i+1, w.Code)
		}
	}
}

// Every operation that takes a body rejects an undeclared field with 400, so
// the closed request schemas in the OpenAPI spec hold.
func TestUnknownRequestFieldsAreRejected(t *testing.T) {
	setupHandlerTest(t)
	account, _ := seedAccount(t, "alice", "default", "0xaaa4")

	cases := []struct{ path, body string }{
		{"/v1/devices/init", `{"chainId":80002}`},
		{"/v1/devices/register", `{"chainId":80002,"address":"0xaaa4","share":"s"}`},
		{"/v1/devices", `{"accountId":"` + account.ID + `","address":"0xaaa4","chainId":80002,"share":"s"}`},
		{"/v2/devices/create", `{"accountType":"eoa","chainType":"evm","chainId":80002,"address":"0xnew4","share":"s"}`},
		{"/v2/devices/recover", `{"account":"` + account.ID + `"}`},
		{"/v2/devices/register", `{"account":"` + account.ID + `","share":"s"}`},
		{"/v2/accounts/import-share", `{"address":"0ximp4","share":"s","userId":"legacy","custody":"User"}`},
	}
	for _, c := range cases {
		post := func(body string) int {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, c.path, strings.NewReader(body))
			apiMux().ServeHTTP(w, asUser(r, "alice", "default"))
			return w.Code
		}
		undeclared := strings.TrimSuffix(c.body, "}") + `,"unexpected":1}`
		if code := post(undeclared); code != http.StatusBadRequest {
			t.Fatalf("%s with an undeclared field got %d, want 400", c.path, code)
		}
		if code := post(c.body); code == http.StatusBadRequest {
			t.Fatalf("%s with its documented body got 400", c.path)
		}
	}
}

// migrated-data returns the three documented fields, not the stored row.
func TestMigratedDataResponseHasOnlyDocumentedFields(t *testing.T) {
	setupHandlerTest(t)
	account, _ := seedAccount(t, "alice", "default", "0xaaa5")
	row := MigratedAccountData{ID: account.ID, Wallet: "w1", FormerOwnerUser: "legacy"}
	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("seed migrated data: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/v2/accounts/migrated-data?accountId="+account.ID, nil)
	apiMux().ServeHTTP(w, asUser(r, "alice", "default"))
	if w.Code != http.StatusOK {
		t.Fatalf("migrated-data got %d, want 200", w.Code)
	}
	var got map[string]any
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(got) != 3 || got["id"] != account.ID || got["wallet"] != "w1" || got["former_user"] != "legacy" {
		t.Fatalf("got %v, want exactly id, wallet and former_user", got)
	}
}

// ---- Device list and revocation (HOT-1, HOT-2, HOT-3) ----

func seedSecondaryDevice(t *testing.T, account Account) Device {
	t.Helper()
	device, err := newDevice("share-secondary", account.SignerId, false)
	if err != nil {
		t.Fatalf("seed secondary device: %v", err)
	}
	if err := db.Create(&device).Error; err != nil {
		t.Fatalf("seed secondary device row: %v", err)
	}
	return device
}

func serve(t *testing.T, method, path, userId, provider string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	apiMux().ServeHTTP(w, asUser(httptest.NewRequest(method, path, nil), userId, provider))
	return w
}

func reloadDevice(t *testing.T, id string) Device {
	t.Helper()
	var row Device
	if err := db.First(&row, "id = ?", id).Error; err != nil {
		t.Fatalf("reload device %s: %v", id, err)
	}
	return row
}

func TestRevokeSecondaryDeviceClearsShareAndHidesIt(t *testing.T) {
	setupHandlerTest(t)
	account, _ := seedAccount(t, "alice", "default", "0xrev1")
	secondary := seedSecondaryDevice(t, account)

	if w := serve(t, http.MethodDelete, "/v2/devices/"+secondary.ID, "alice", "default"); w.Code != http.StatusNoContent {
		t.Fatalf("revoke got %d, want 204: %s", w.Code, w.Body.String())
	}
	row := reloadDevice(t, secondary.ID)
	if row.Share != "" || row.RevokedAt == nil {
		t.Fatalf("after revoke share=%q revokedAt=%v, want an empty share and a timestamp", row.Share, row.RevokedAt)
	}
	if w := serve(t, http.MethodGet, "/v1/devices/"+secondary.ID, "alice", "default"); w.Code != http.StatusNotFound {
		t.Fatalf("GET on a revoked device got %d, want 404", w.Code)
	}

	w := serve(t, http.MethodGet, "/v2/devices", "alice", "default")
	if w.Code != http.StatusOK {
		t.Fatalf("list got %d, want 200", w.Code)
	}
	var list DeviceSummaryListResponse
	if err := json.NewDecoder(w.Body).Decode(&list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	var found *DeviceSummary
	for i := range list.Data {
		if list.Data[i].ID == secondary.ID {
			found = &list.Data[i]
		}
	}
	if found == nil || !found.Revoked || found.RevokedAt == nil {
		t.Fatalf("revoked device in the list: %+v, want revoked:true with revokedAt", found)
	}
}

func TestRevokePrimaryDeviceIsRefused(t *testing.T) {
	setupHandlerTest(t)
	_, primary := seedAccount(t, "alice", "default", "0xrev2")

	if w := serve(t, http.MethodDelete, "/v2/devices/"+primary.ID, "alice", "default"); w.Code != http.StatusConflict {
		t.Fatalf("revoke primary got %d, want 409", w.Code)
	}
	row := reloadDevice(t, primary.ID)
	if row.Share != primary.Share || row.RevokedAt != nil {
		t.Fatalf("primary row changed by a refused revoke: share kept=%v revokedAt=%v", row.Share == primary.Share, row.RevokedAt)
	}
}

func TestRevokeIsScopedToOwner(t *testing.T) {
	setupHandlerTest(t)
	bobAccount, _ := seedAccount(t, "bob", "default", "0xrev3")
	bobSecondary := seedSecondaryDevice(t, bobAccount)
	seedAccount(t, "alice", "default", "0xrev3a")

	if w := serve(t, http.MethodDelete, "/v2/devices/"+bobSecondary.ID, "alice", "default"); w.Code != http.StatusNotFound {
		t.Fatalf("alice revoking bob's device got %d, want 404", w.Code)
	}
	// Same username under another provider is a different subject.
	if w := serve(t, http.MethodDelete, "/v2/devices/"+bobSecondary.ID, "bob", "google"); w.Code != http.StatusNotFound {
		t.Fatalf("bob@google revoking bob@default's device got %d, want 404", w.Code)
	}
	row := reloadDevice(t, bobSecondary.ID)
	if row.Share == "" || row.RevokedAt != nil {
		t.Fatalf("row changed by a non-owner: share empty=%v revokedAt=%v", row.Share == "", row.RevokedAt)
	}
}

func TestRevokeTwiceIsNotFound(t *testing.T) {
	setupHandlerTest(t)
	account, _ := seedAccount(t, "alice", "default", "0xrev4")
	secondary := seedSecondaryDevice(t, account)

	if w := serve(t, http.MethodDelete, "/v2/devices/"+secondary.ID, "alice", "default"); w.Code != http.StatusNoContent {
		t.Fatalf("first revoke got %d, want 204", w.Code)
	}
	if w := serve(t, http.MethodDelete, "/v2/devices/"+secondary.ID, "alice", "default"); w.Code != http.StatusNotFound {
		t.Fatalf("second revoke got %d, want 404", w.Code)
	}
}

func TestRevokeRejectsOtherMethods(t *testing.T) {
	setupHandlerTest(t)
	account, _ := seedAccount(t, "alice", "default", "0xrev5")
	secondary := seedSecondaryDevice(t, account)

	if w := serve(t, http.MethodGet, "/v2/devices/"+secondary.ID, "alice", "default"); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /v2/devices/{id} got %d, want 405", w.Code)
	}
	if w := serve(t, http.MethodPost, "/v2/devices", "alice", "default"); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /v2/devices got %d, want 405", w.Code)
	}
}

func TestListDevicesV2OmitsSharesAndOrdersByCreation(t *testing.T) {
	setupHandlerTest(t)
	account, primary := seedAccount(t, "alice", "default", "0xlist1")
	secondary := seedSecondaryDevice(t, account)

	w := serve(t, http.MethodGet, "/v2/devices", "alice", "default")
	if w.Code != http.StatusOK {
		t.Fatalf("list got %d, want 200", w.Code)
	}
	raw := w.Body.String()
	if strings.Contains(raw, `"share"`) {
		t.Fatalf("v2 device list must not carry shares: %s", raw)
	}
	var list DeviceSummaryListResponse
	if err := json.NewDecoder(strings.NewReader(raw)).Decode(&list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if list.Total != 2 || len(list.Data) != 2 {
		t.Fatalf("got %d devices, want 2", list.Total)
	}
	if list.Data[0].ID != primary.ID || !list.Data[0].IsPrimary {
		t.Fatalf("first entry %+v, want the primary device", list.Data[0])
	}
	if list.Data[1].ID != secondary.ID || list.Data[1].IsPrimary || list.Data[1].Revoked {
		t.Fatalf("second entry %+v, want the live secondary device", list.Data[1])
	}
	if list.Data[0].CreatedAt <= 0 || list.Data[0].Object != "device" {
		t.Fatalf("entry metadata %+v, want createdAt and object", list.Data[0])
	}
}

func TestListDevicesV2IsScopedToUserAndProvider(t *testing.T) {
	setupHandlerTest(t)
	seedAccount(t, "alice", "default", "0xlist2")
	seedAccount(t, "bob", "default", "0xlist2b")
	seedAccount(t, "alice", "google", "0xlist2g")

	w := serve(t, http.MethodGet, "/v2/devices", "alice", "default")
	var list DeviceSummaryListResponse
	if err := json.NewDecoder(w.Body).Decode(&list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if list.Total != 1 {
		t.Fatalf("alice@default sees %d device(s), want only her own", list.Total)
	}
}

func TestRevokedDeviceIsHiddenFromV1List(t *testing.T) {
	setupHandlerTest(t)
	account, _ := seedAccount(t, "alice", "default", "0xlist3")
	secondary := seedSecondaryDevice(t, account)
	if w := serve(t, http.MethodDelete, "/v2/devices/"+secondary.ID, "alice", "default"); w.Code != http.StatusNoContent {
		t.Fatalf("revoke got %d, want 204", w.Code)
	}

	w := serve(t, http.MethodGet, "/v1/devices", "alice", "default")
	var list DeviceListResponse
	if err := json.NewDecoder(w.Body).Decode(&list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if list.Total != 1 || !list.Data[0].IsPrimary {
		t.Fatalf("v1 list after revoke: %+v, want only the primary device", list.Data)
	}
}

func TestRecoverV2IgnoresRevokedPrimaryLookup(t *testing.T) {
	setupHandlerTest(t)
	account, primary := seedAccount(t, "alice", "default", "0xrec1")
	// Defensive: a primary row cannot be revoked through the API (409), but a row
	// carrying revoked_at must never be served, whichever way it got there.
	if err := db.Model(&Device{}).Where("id = ?", primary.ID).Updates(map[string]any{"share": "", "revoked_at": time.Now()}).Error; err != nil {
		t.Fatalf("mark primary revoked: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v2/devices/recover", strings.NewReader(`{"account":"`+account.ID+`"}`))
	apiMux().ServeHTTP(w, asUser(r, "alice", "default"))
	if w.Code == http.StatusOK {
		t.Fatalf("recover served a revoked primary row: %s", w.Body.String())
	}
}
