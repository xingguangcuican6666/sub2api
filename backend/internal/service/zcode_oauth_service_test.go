package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// zcodeBizKeyServer 按 method 返回列表/创建响应；listShape 控制 GET 的壳形状。
type zcodeBizKeyServer struct {
	*httptest.Server
	createCalls   int32
	listCalls     int32
	failFirstList bool
	listShape     string // "data-array"（{"code":0,"data":[...]}）或 "top-array"（顶层数组）
}

func newZcodeBizKeyServer(t *testing.T) *zcodeBizKeyServer {
	t.Helper()
	biz := &zcodeBizKeyServer{listShape: "data-array"}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		if r.Method == http.MethodPost {
			atomic.AddInt32(&biz.createCalls, 1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code": 500,
				"msg":  "Creation failed. apiKey name [zcode-api-key] is duplicate",
			})
			return
		}
		if atomic.AddInt32(&biz.listCalls, 1) == 1 && biz.failFirstList {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
			return
		}
		keys := []any{
			map[string]any{"name": "other-key", "apiKey": "otherKeyValue"},
			map[string]any{"name": ZcodeAPIKeyName, "apiKey": "existingKeyValue"},
		}
		if biz.listShape == "top-array" {
			_ = json.NewEncoder(w).Encode(keys)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "data": keys})
	})
	biz.Server = httptest.NewServer(mux)
	t.Cleanup(biz.Close)
	return biz
}

// biz API 列表端点返回 {"code":0,"data":[...]}（data 为数组）时必须解包并复用
// 已有 Key。曾因 bizAPI 只解包 data 为对象的壳，列表被误判为空 → 走创建 →
// 撞同名 Key 的 500 duplicate，账号已有 zcode-api-key 时第二次登录永远失败。
func TestZcodeFindOrCreateAPIKeyReusesKeyInDataArrayEnvelope(t *testing.T) {
	biz := newZcodeBizKeyServer(t)

	svc := &ZcodeOAuthService{}
	apiKey, err := svc.findOrCreateAPIKey(context.Background(), biz.Client(), biz.URL, "Bearer tok", "org1", "proj1")

	require.NoError(t, err)
	require.Equal(t, "existingKeyValue", apiKey)
	require.Zero(t, atomic.LoadInt32(&biz.createCalls), "existing key must be reused, not re-created")
}

func TestZcodeFindOrCreateAPIKeyReusesKeyInTopLevelArray(t *testing.T) {
	biz := newZcodeBizKeyServer(t)
	biz.listShape = "top-array"

	svc := &ZcodeOAuthService{}
	apiKey, err := svc.findOrCreateAPIKey(context.Background(), biz.Client(), biz.URL, "Bearer tok", "org1", "proj1")

	require.NoError(t, err)
	require.Equal(t, "existingKeyValue", apiKey)
	require.Zero(t, atomic.LoadInt32(&biz.createCalls))
}

// 首次列表瞬时失败被忽略后（resolver.ts 同语义），创建撞 duplicate 时应重试
// 一次列表并复用已有 Key，而不是把 500 duplicate 抛给登录流程。
func TestZcodeFindOrCreateAPIKeyRecoversFromDuplicateCreate(t *testing.T) {
	biz := newZcodeBizKeyServer(t)
	biz.failFirstList = true

	svc := &ZcodeOAuthService{}
	apiKey, err := svc.findOrCreateAPIKey(context.Background(), biz.Client(), biz.URL, "Bearer tok", "org1", "proj1")

	require.NoError(t, err)
	require.Equal(t, "existingKeyValue", apiKey)
	require.Equal(t, int32(1), atomic.LoadInt32(&biz.createCalls))
	require.Equal(t, int32(2), atomic.LoadInt32(&biz.listCalls))
}

func TestZcodeFindOrCreateAPIKeyCreatesWhenListEmpty(t *testing.T) {
	var createCalls int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		if r.Method == http.MethodPost {
			atomic.AddInt32(&createCalls, 1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code": 0,
				"data": map[string]any{"apiKey": "newKeyValue"},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "data": []any{}})
	}))
	defer ts.Close()

	svc := &ZcodeOAuthService{}
	apiKey, err := svc.findOrCreateAPIKey(context.Background(), ts.Client(), ts.URL, "Bearer tok", "org1", "proj1")

	require.NoError(t, err)
	require.Equal(t, "newKeyValue", apiKey)
	require.Equal(t, int32(1), atomic.LoadInt32(&createCalls))
}

// bizAPI 必须同时解包顶层数组与 data 为数组的壳（{"code":0,"data":[...]}）。
func TestZcodeBizAPIUnwrapsListEnvelopes(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"top-level array", `[{"name":"zcode-api-key","apiKey":"k1"}]`},
		{"data array envelope", `{"code":0,"data":[{"name":"zcode-api-key","apiKey":"k1"}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("content-type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			}))
			defer ts.Close()

			svc := &ZcodeOAuthService{}
			data, err := svc.bizAPI(context.Background(), ts.Client(), http.MethodGet, ts.URL, "Bearer tok", nil)

			require.NoError(t, err)
			list, ok := data["_list"].([]any)
			require.True(t, ok, "list response should be wrapped as _list")
			require.Len(t, list, 1)
		})
	}
}
