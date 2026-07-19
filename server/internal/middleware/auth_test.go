package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/multica-ai/multica/server/internal/auth"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
	"github.com/redis/go-redis/v9"
)

const redisTestDB = 13

// newRedisTestClient connects to REDIS_TEST_URL, uses this package's logical
// test DB, flushes, and skips when unset — same gating pattern the rest of the
// suite uses for Redis-backed tests, so `go test ./...` works on a stock laptop
// without a Redis.
func newRedisTestClient(t *testing.T) *redis.Client {
	t.Helper()
	url := os.Getenv("REDIS_TEST_URL")
	if url == "" {
		t.Skip("REDIS_TEST_URL not set")
	}
	opts, err := redis.ParseURL(url)
	if err != nil {
		t.Fatalf("parse REDIS_TEST_URL: %v", err)
	}
	opts.DB = redisTestDB
	rdb := redis.NewClient(opts)
	ctx := context.Background()
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Skipf("REDIS_TEST_URL unreachable: %v", err)
	}
	if err := rdb.FlushDB(ctx).Err(); err != nil {
		t.Fatalf("flushdb: %v", err)
	}
	t.Cleanup(func() {
		rdb.FlushDB(context.Background())
		rdb.Close()
	})
	return rdb
}

func TestAuth_ServiceAccountStampsIndependentPrincipal(t *testing.T) {
	pool := openPool(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	var userID, workspaceID, serviceID string
	if err := pool.QueryRow(ctx, `INSERT INTO "user" (name,email) VALUES ('Service Creator','service-auth-test@multica.test') RETURNING id`).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO workspace (name,slug,issue_prefix) VALUES ('Service Auth Test','service-auth-test','SAT') RETURNING id`).Scan(&workspaceID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO service_account (workspace_id,name,slug,role,created_by_user_id) VALUES ($1,'GRIT Admin','grit-admin','member',$2) RETURNING id`, workspaceID, userID).Scan(&serviceID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx := context.Background()
		if _, err := pool.Exec(cleanupCtx, `DELETE FROM workspace WHERE id=$1`, workspaceID); err != nil {
			t.Errorf("delete service auth workspace fixture: %v", err)
		}
		if _, err := pool.Exec(cleanupCtx, `DELETE FROM "user" WHERE id=$1`, userID); err != nil {
			t.Errorf("delete service auth user fixture: %v", err)
		}
	})
	raw, err := auth.GenerateServiceAccountToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO service_account_token (service_account_id,name,token_hash,token_prefix) VALUES ($1,'test',$2,'msa_test')`, serviceID, auth.HashToken(raw)); err != nil {
		t.Fatal(err)
	}

	var gotUser, gotService, gotRole, gotWorkspace, gotSource string
	handler := Auth(db.New(pool), nil, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotService = r.Header.Get("X-User-ID"), r.Header.Get("X-Service-Account-ID")
		gotRole, gotWorkspace, gotSource = r.Header.Get("X-Service-Account-Role"), r.Header.Get("X-Workspace-ID"), r.Header.Get("X-Actor-Source")
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/issues", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if gotUser != serviceID || gotService != serviceID || gotRole != "member" || gotWorkspace != workspaceID || gotSource != "service_account" {
		t.Fatalf("principal user=%s service=%s role=%s workspace=%s source=%s", gotUser, gotService, gotRole, gotWorkspace, gotSource)
	}
}

func TestAuth_ServiceAccountWorkspaceDeletionRevokesToken(t *testing.T) {
	pool := openPool(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	var userID, workspaceID, serviceID string
	if err := pool.QueryRow(ctx, `INSERT INTO "user" (name,email) VALUES ('Lifecycle Creator','service-lifecycle-test@multica.test') RETURNING id`).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO workspace (name,slug,issue_prefix) VALUES ('Service Lifecycle Test','service-lifecycle-test','SLT') RETURNING id`).Scan(&workspaceID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO service_account (workspace_id,name,slug,role,created_by_user_id) VALUES ($1,'Lifecycle Service','lifecycle-service','member',$2) RETURNING id`, workspaceID, userID).Scan(&serviceID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx := context.Background()
		if _, err := pool.Exec(cleanupCtx, `DELETE FROM workspace WHERE id=$1`, workspaceID); err != nil {
			t.Errorf("delete service lifecycle workspace fixture: %v", err)
		}
		if _, err := pool.Exec(cleanupCtx, `DELETE FROM "user" WHERE id=$1`, userID); err != nil {
			t.Errorf("delete service lifecycle user fixture: %v", err)
		}
	})
	raw, err := auth.GenerateServiceAccountToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO service_account_token (service_account_id,name,token_hash,token_prefix) VALUES ($1,'lifecycle',$2,$3)`, serviceID, auth.HashToken(raw), raw[:12]); err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(ctx, `DELETE FROM workspace WHERE id=$1`, workspaceID); err != nil {
		t.Fatal(err)
	}
	var accountCount, tokenCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM service_account WHERE id=$1`, serviceID).Scan(&accountCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM service_account_token WHERE service_account_id=$1`, serviceID).Scan(&tokenCount); err != nil {
		t.Fatal(err)
	}
	if accountCount != 0 || tokenCount != 0 {
		t.Fatalf("workspace deletion left service rows: accounts=%d tokens=%d", accountCount, tokenCount)
	}

	handler := Auth(db.New(pool), nil, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("deleted workspace token reached authenticated handler")
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/issues", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s, want 401", w.Code, w.Body.String())
	}
}

func generateToken(claims jwt.MapClaims, secret []byte) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, _ := token.SignedString(secret)
	return s
}

func validClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"sub":   "test-user-id",
		"email": "test@multica.ai",
		"exp":   time.Now().Add(time.Hour).Unix(),
	}
}

// authMiddleware returns the Auth middleware with nil queries (JWT-only tests).
func authMiddleware(next http.Handler) http.Handler {
	return Auth(nil, nil, nil)(next)
}

func TestAuth_MissingHeader(t *testing.T) {
	handler := authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/api/me", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	if body := w.Body.String(); body != `{"error":"missing authorization"}`+"\n" {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestAuth_NoBearerPrefix(t *testing.T) {
	handler := authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/api/me", nil)
	req.Header.Set("Authorization", "Token some-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	// Non-Bearer Authorization header with no cookie falls through to "missing authorization".
	if body := w.Body.String(); body != `{"error":"missing authorization"}`+"\n" {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestAuth_InvalidToken(t *testing.T) {
	handler := authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/api/me", nil)
	req.Header.Set("Authorization", "Bearer not-a-valid-jwt")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAuth_ExpiredToken(t *testing.T) {
	handler := authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))

	claims := validClaims()
	claims["exp"] = time.Now().Add(-time.Hour).Unix()
	token := generateToken(claims, auth.JWTSecret())

	req := httptest.NewRequest("GET", "/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAuth_WrongSecret(t *testing.T) {
	handler := authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))

	token := generateToken(validClaims(), []byte("wrong-secret"))

	req := httptest.NewRequest("GET", "/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAuth_WrongSigningMethod(t *testing.T) {
	handler := authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))

	// Use "none" signing method
	token := jwt.NewWithClaims(jwt.SigningMethodNone, validClaims())
	s, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)

	req := httptest.NewRequest("GET", "/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+s)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAuth_ValidToken(t *testing.T) {
	var gotUserID, gotEmail string
	handler := authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserID = r.Header.Get("X-User-ID")
		gotEmail = r.Header.Get("X-User-Email")
		w.WriteHeader(http.StatusOK)
	}))

	token := generateToken(validClaims(), auth.JWTSecret())

	req := httptest.NewRequest("GET", "/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if gotUserID != "test-user-id" {
		t.Fatalf("expected X-User-ID 'test-user-id', got '%s'", gotUserID)
	}
	if gotEmail != "test@multica.ai" {
		t.Fatalf("expected X-User-Email 'test@multica.ai', got '%s'", gotEmail)
	}
}

func TestAuth_MissingClaims(t *testing.T) {
	handler := authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))

	// Token with no sub or email claims, only exp
	claims := jwt.MapClaims{
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := generateToken(claims, auth.JWTSecret())

	req := httptest.NewRequest("GET", "/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAuth_InvalidPAT(t *testing.T) {
	handler := authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/api/me", nil)
	req.Header.Set("Authorization", "Bearer mul_invalid_token_here")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// TestAuth_StripsClientSuppliedActorSource enforces the invariant that
// X-Actor-Source is a server-only header: any value the client sends
// must be discarded before downstream code sees it. Without this
// guarantee a client carrying a normal mul_ PAT could supply a forged
// `X-Actor-Source: task_token` (or any other value) to fool a handler
// into treating the request differently — exactly the kind of trust
// boundary MUL-2600 introduces.
func TestAuth_StripsClientSuppliedActorSource(t *testing.T) {
	var gotActorSource string
	mw := Auth(nil, nil, nil)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotActorSource = r.Header.Get("X-Actor-Source")
		w.WriteHeader(http.StatusOK)
	}))

	token := generateToken(validClaims(), auth.JWTSecret())
	req := httptest.NewRequest("GET", "/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	// Client tries to forge the actor-source header. The middleware must
	// discard it before the JWT branch runs (which doesn't set it again
	// for human sessions).
	req.Header.Set("X-Actor-Source", "task_token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if gotActorSource != "" {
		t.Fatalf("X-Actor-Source must be cleared on non-task-token paths, got %q", gotActorSource)
	}
}

// TestAuth_PATCacheHit pins the optimization: when the PAT cache already
// holds an entry for this token, the middleware MUST NOT call into queries
// — it short-circuits before the DB lookup and the last_used_at update.
//
// We exploit that by passing nil queries: a cache miss would dereference
// the nil and panic; a cache hit must not. Reaching the next handler with
// the cached user_id therefore proves the short-circuit fired.
func TestAuth_PATCacheHit(t *testing.T) {
	rdb := newRedisTestClient(t)
	cache := auth.NewPATCache(rdb)
	if cache == nil {
		t.Fatal("expected non-nil cache")
	}

	const rawToken = "mul_cache_hit_test_token"
	hash := auth.HashToken(rawToken)
	cache.Set(context.Background(), hash, "cached-user-id", auth.AuthCacheTTL)

	var gotUserID string
	mw := Auth(nil, cache, nil) // nil queries — only safe on cache hit
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserID = r.Header.Get("X-User-ID")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on cache hit, got %d", w.Code)
	}
	if gotUserID != "cached-user-id" {
		t.Fatalf("expected cached X-User-ID, got %q", gotUserID)
	}
}

// TestAuth_MCN_NoVerifierConfigured pins the same fail-closed branch
// as the daemon side: with no MULTICA_CLOUD_FLEET_URL configured, an
// mcn_ bearer token must be rejected with 401 at the prefix branch.
// We don't fall through — an mcn_ string can't be a valid mul_ PAT or
// JWT, so any fall-through would be wasted work.
func TestAuth_MCN_NoVerifierConfigured(t *testing.T) {
	mw := Auth(nil, nil, nil)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next must not be called when verifier is unconfigured")
	}))
	req := httptest.NewRequest("GET", "/api/me", nil)
	req.Header.Set("Authorization", "Bearer mcn_anything")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// TestAuth_MCN_ValidTokenSetsUserID is the happy-path mirror of the
// daemon test: a successful Fleet verify must surface owner_id as
// X-User-ID for downstream user-scoped handlers.
func TestAuth_MCN_ValidTokenSetsUserID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"valid": true,
			"owner_id": "01972f7e-7e8d-77ef-a13d-1b0ce3e9c001"
		}`))
	}))
	defer srv.Close()

	verifier := auth.NewCloudPATVerifier(auth.CloudPATVerifierConfig{FleetBaseURL: srv.URL})

	var gotUser, gotActorSource string
	mw := Auth(nil, nil, verifier)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser = r.Header.Get("X-User-ID")
		gotActorSource = r.Header.Get("X-Actor-Source")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/me", nil)
	req.Header.Set("Authorization", "Bearer mcn_x")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if gotUser != "01972f7e-7e8d-77ef-a13d-1b0ce3e9c001" {
		t.Errorf("expected owner_id propagated as X-User-ID, got %q", gotUser)
	}
	// Pinned per the cloud-billing review: a successful mcn_ verify
	// MUST stamp X-Actor-Source so account-level guards (e.g.
	// handler.RequireHumanActor on /api/cloud-billing/*) can tell a
	// machine credential apart from a human PAT/JWT. Dropping this
	// stamp would silently let an mcn_ holder reach billing.
	if gotActorSource != "cloud_pat" {
		t.Errorf("expected X-Actor-Source=cloud_pat, got %q", gotActorSource)
	}
}

// TestAuth_MCN_InvalidReturns401 confirms that a Fleet valid:false maps
// to 401 — the token is genuinely bad, retrying won't help.
func TestAuth_MCN_InvalidReturns401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"valid":false,"reason":"token_revoked"}`))
	}))
	defer srv.Close()

	verifier := auth.NewCloudPATVerifier(auth.CloudPATVerifierConfig{FleetBaseURL: srv.URL})
	mw := Auth(nil, nil, verifier)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next must not be called when token is invalid")
	}))

	req := httptest.NewRequest("GET", "/api/me", nil)
	req.Header.Set("Authorization", "Bearer mcn_revoked")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// TestAuth_MCN_FleetUnreachableReturns503 — the Unavailable branch must
// emit 503 (transient), distinguishing it from a 401 (token is bad).
func TestAuth_MCN_FleetUnreachableReturns503(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	verifier := auth.NewCloudPATVerifier(auth.CloudPATVerifierConfig{FleetBaseURL: srv.URL})
	mw := Auth(nil, nil, verifier)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next must not be called when fleet is unavailable")
	}))

	req := httptest.NewRequest("GET", "/api/me", nil)
	req.Header.Set("Authorization", "Bearer mcn_x")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
}
