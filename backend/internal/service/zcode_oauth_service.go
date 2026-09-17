package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/httpclient"
)

// ZCode OAuth 登录服务（对齐 TriDefender/zcode-api 的 auth/oauth.ts + auth/resolver.ts）。
//
// 两个上游 provider 使用不同的登录流程：
//   - zai（Z.AI）：服务端中转 CLI 登录。POST {ZcodeAPIBase}/oauth/cli/init 拿到
//     服务端生成的 authorize_url（redirect_uri 为 zcode.z.ai 自己的回调），客户端
//     轮询 /oauth/cli/poll/{flow_id} 直到 status=ready。无本地回调。
//   - bigmodel（智谱）：经典 auth-code 流程。authorize 于 bigmodel.cn/login?appId=zcode，
//     回调 redirect 指向 127.0.0.1（无本地监听，浏览器打不开即展示在地址栏），
//     用户把最终 URL 粘贴回来，后端校验 state 后到 zcode.z.ai 换 token。
//
// 换取到的 access_token 再经 KeyResolver 解析为 Coding Plan 永久 API Key
// （自动在默认机构/项目下查找或创建名为 zcode-api-key 的 Key）。

const (
	zcodeLoginTimeout = 300 * time.Second
	zcodeSessionTTL   = 30 * time.Minute

	// zcodeOAuthCallbackHost 是 bigmodel 粘贴模式下的固定 redirect（无本地监听，
	// 仅用于承载回调 query；用户复制浏览器地址栏 URL 粘贴回来）。
	zcodeOAuthCallbackHost = "http://127.0.0.1:62156/oauth/callback/bigmodel"
)

// ZcodeOAuthSession 是一次进行中的登录流程。
type ZcodeOAuthSession struct {
	Provider    string
	FlowID      string // zai cli flow
	PollToken   string // zai cli flow
	State       string // bigmodel auth-code flow
	RedirectURI string // bigmodel auth-code flow
	ProxyID     *int64
	CreatedAt   time.Time
}

// zcodeSessionStore 内存会话存储（TTL 清理，模式对齐 geminicli.SessionStore）。
type zcodeSessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*ZcodeOAuthSession
	stopCh   chan struct{}
}

func newZcodeSessionStore() *zcodeSessionStore {
	store := &zcodeSessionStore{
		sessions: make(map[string]*ZcodeOAuthSession),
		stopCh:   make(chan struct{}),
	}
	go store.cleanup()
	return store
}

func (s *zcodeSessionStore) Set(id string, session *ZcodeOAuthSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = session
}

func (s *zcodeSessionStore) Get(id string) (*ZcodeOAuthSession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[id]
	if !ok || time.Since(session.CreatedAt) > zcodeSessionTTL {
		return nil, false
	}
	return session, true
}

func (s *zcodeSessionStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

func (s *zcodeSessionStore) Stop() {
	select {
	case <-s.stopCh:
		return
	default:
		close(s.stopCh)
	}
}

func (s *zcodeSessionStore) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.mu.Lock()
			for id, session := range s.sessions {
				if time.Since(session.CreatedAt) > zcodeSessionTTL {
					delete(s.sessions, id)
				}
			}
			s.mu.Unlock()
		}
	}
}

// ZcodeOAuthService 提供 ZCode 登录流程与 Coding Plan 凭证解析。
type ZcodeOAuthService struct {
	sessionStore *zcodeSessionStore
	proxyRepo    ProxyRepository
	httpClient   *http.Client
}

func NewZcodeOAuthService(proxyRepo ProxyRepository) *ZcodeOAuthService {
	client, err := httpclient.GetClient(httpclient.Options{Timeout: 30 * time.Second})
	if err != nil {
		// 共享池失败时退回默认客户端（无代理直连场景）。
		client = http.DefaultClient
	}
	return &ZcodeOAuthService{
		sessionStore: newZcodeSessionStore(),
		proxyRepo:    proxyRepo,
		httpClient:   client,
	}
}

// Stop 停止会话清理 goroutine（服务关闭时调用）。
func (s *ZcodeOAuthService) Stop() {
	s.sessionStore.Stop()
}

// clientFor 返回按代理配置构建的 HTTP 客户端；proxyID 为空时用默认客户端。
func (s *ZcodeOAuthService) clientFor(ctx context.Context, proxyID *int64) (*http.Client, error) {
	if proxyID == nil || *proxyID == 0 {
		return s.httpClient, nil
	}
	proxy, err := s.proxyRepo.GetByID(ctx, *proxyID)
	if err != nil || proxy == nil {
		return nil, fmt.Errorf("proxy %d not found", *proxyID)
	}
	return httpclient.GetClient(httpclient.Options{
		ProxyURL: proxy.URL(),
		Timeout:  30 * time.Second,
	})
}

// zcodeEnvelope 是 zcode.z.ai 控制面的 {code, data, msg} 响应壳。
type zcodeEnvelope struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

func (e *zcodeEnvelope) ok() bool { return e.Code == 0 }

// zcodePostJSON 发送 JSON POST 并解包 zcode 控制面响应壳。
func (s *ZcodeOAuthService) zcodePostJSON(ctx context.Context, client *http.Client, target, label string, headers map[string]string, body any) (*zcodeEnvelope, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("%s: encode body: %w", label, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("%s: build request: %w", label, err)
	}
	req.Header.Set("content-type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return s.zcodeDo(client, req, label)
}

// zcodeGet 发送 GET 并解包 zcode 控制面响应壳。
func (s *ZcodeOAuthService) zcodeGet(ctx context.Context, client *http.Client, target, label string, headers map[string]string) (*zcodeEnvelope, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: build request: %w", label, err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return s.zcodeDo(client, req, label)
}

func (s *ZcodeOAuthService) zcodeDo(client *http.Client, req *http.Request, label string) (*zcodeEnvelope, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: request failed: %w", label, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return nil, fmt.Errorf("%s: read response: %w", label, err)
	}
	var envelope zcodeEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("%s: invalid response envelope (status=%d body=%s)", label, resp.StatusCode, truncateZcodeBody(raw))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !envelope.ok() {
		return nil, fmt.Errorf("%s failed: status=%d code=%d msg=%s", label, resp.StatusCode, envelope.Code, envelope.Msg)
	}
	return &envelope, nil
}

func truncateZcodeBody(raw []byte) string {
	text := strings.TrimSpace(string(raw))
	if len(text) > 200 {
		return text[:200]
	}
	return text
}

// ZcodeAuthURLResult 是 StartLogin 的返回结构。
type ZcodeAuthURLResult struct {
	Mode        string `json:"mode"` // "poll"（zai）或 "paste"（bigmodel）
	AuthURL     string `json:"auth_url"`
	SessionID   string `json:"session_id"`
	RedirectURI string `json:"redirect_uri,omitempty"` // paste 模式：回调地址提示
	ExpiresAt   int64  `json:"expires_at,omitempty"`   // poll 模式：flow 过期时间（unix 秒）
}

// StartLogin 发起 ZCode OAuth 登录，返回授权 URL。
func (s *ZcodeOAuthService) StartLogin(ctx context.Context, provider string, proxyID *int64) (*ZcodeAuthURLResult, error) {
	provider = strings.TrimSpace(provider)
	if provider != ZcodeProviderZai && provider != ZcodeProviderBigmodel {
		return nil, fmt.Errorf("unsupported zcode provider: %s (must be zai or bigmodel)", provider)
	}
	sessionID, err := zcodeRandomToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	switch provider {
	case ZcodeProviderZai:
		pollToken, err := zcodeRandomToken()
		if err != nil {
			return nil, fmt.Errorf("failed to generate poll token: %w", err)
		}
		client, err := s.clientFor(ctx, proxyID)
		if err != nil {
			return nil, err
		}
		envelope, err := s.zcodePostJSON(ctx, client, ZcodeAPIBase+"/oauth/cli/init", "Z.AI login init",
			map[string]string{"authorization": "Bearer " + pollToken},
			map[string]string{"provider": ZcodeProviderZai})
		if err != nil {
			return nil, err
		}
		var data struct {
			FlowID          string `json:"flow_id"`
			PollToken       string `json:"poll_token"`
			AuthorizeURL    string `json:"authorize_url"`
			ExpiresAt       int64  `json:"expires_at"`
			PollIntervalSec int    `json:"poll_interval_sec"`
		}
		if err := json.Unmarshal(envelope.Data, &data); err != nil || data.FlowID == "" || data.AuthorizeURL == "" {
			return nil, fmt.Errorf("Z.AI login init: invalid response data")
		}
		s.sessionStore.Set(sessionID, &ZcodeOAuthSession{
			Provider:  ZcodeProviderZai,
			FlowID:    data.FlowID,
			PollToken: pollToken,
			ProxyID:   proxyID,
			CreatedAt: time.Now(),
		})
		return &ZcodeAuthURLResult{
			Mode:      "poll",
			AuthURL:   data.AuthorizeURL,
			SessionID: sessionID,
			ExpiresAt: data.ExpiresAt,
		}, nil

	default: // bigmodel
		state, err := zcodeRandomToken()
		if err != nil {
			return nil, fmt.Errorf("failed to generate state: %w", err)
		}
		params := url.Values{}
		params.Set("appId", ZcodeBigmodelAppID)
		params.Set("redirect", zcodeOAuthCallbackHost)
		params.Set("state", state)
		authorizeURL := ZcodeBigmodelAuthorizeBase + "?" + params.Encode()
		s.sessionStore.Set(sessionID, &ZcodeOAuthSession{
			Provider:    ZcodeProviderBigmodel,
			State:       state,
			RedirectURI: zcodeOAuthCallbackHost,
			ProxyID:     proxyID,
			CreatedAt:   time.Now(),
		})
		return &ZcodeAuthURLResult{
			Mode:        "paste",
			AuthURL:     authorizeURL,
			SessionID:   sessionID,
			RedirectURI: zcodeOAuthCallbackHost,
		}, nil
	}
}

// ZcodeLoginStatus 是 PollLogin 的返回结构。status: pending / ready / failed。
type ZcodeLoginStatus struct {
	Status      string         `json:"status"`
	Message     string         `json:"message,omitempty"`
	Credentials map[string]any `json:"credentials,omitempty"`
}

// PollLogin 对 zai cli 流程做一次轮询；ready 时完成凭证解析并返回账号凭据。
// 前端以数秒间隔重复调用直到 ready / failed（避免长挂 HTTP 请求）。
func (s *ZcodeOAuthService) PollLogin(ctx context.Context, sessionID string) (*ZcodeLoginStatus, error) {
	session, ok := s.sessionStore.Get(sessionID)
	if !ok {
		return nil, fmt.Errorf("zcode login session not found or expired, restart the login")
	}
	if session.Provider != ZcodeProviderZai {
		return nil, fmt.Errorf("zcode login session is not a poll-mode (zai) session")
	}
	if time.Since(session.CreatedAt) > zcodeLoginTimeout {
		s.sessionStore.Delete(sessionID)
		return &ZcodeLoginStatus{Status: "failed", Message: "authorization timed out, please retry login"}, nil
	}

	client, err := s.clientFor(ctx, session.ProxyID)
	if err != nil {
		return nil, err
	}
	envelope, err := s.zcodeGet(ctx, client, ZcodeAPIBase+"/oauth/cli/poll/"+url.PathEscape(session.FlowID), "Z.AI login poll",
		map[string]string{"authorization": "Bearer " + session.PollToken})
	if err != nil {
		return nil, err
	}
	var data struct {
		Status string `json:"status"`
		Token  string `json:"token"`
		User   struct {
			UserID string `json:"user_id"`
		} `json:"user"`
		Zai struct {
			AccessToken string `json:"access_token"`
		} `json:"zai"`
	}
	if err := json.Unmarshal(envelope.Data, &data); err != nil {
		return nil, fmt.Errorf("Z.AI login poll: invalid response data")
	}
	switch data.Status {
	case "pending":
		return &ZcodeLoginStatus{Status: "pending"}, nil
	case "failed":
		s.sessionStore.Delete(sessionID)
		return &ZcodeLoginStatus{Status: "failed", Message: "authorization failed, please retry login"}, nil
	case "ready":
		accessToken := strings.TrimSpace(data.Zai.AccessToken)
		if accessToken == "" {
			return nil, fmt.Errorf("Z.AI login poll: response missing data.zai.access_token")
		}
		s.sessionStore.Delete(sessionID)
		credentials, err := s.ResolveCodingPlanCredential(ctx, ZcodeProviderZai, accessToken, data.User.UserID, session.ProxyID)
		if err != nil {
			return nil, err
		}
		if jwt := strings.TrimSpace(data.Token); jwt != "" {
			credentials["jwt"] = jwt
		}
		return &ZcodeLoginStatus{Status: "ready", Credentials: credentials}, nil
	default:
		return nil, fmt.Errorf("Z.AI login poll: unexpected status %s", data.Status)
	}
}

// CompleteBigmodelLogin 用用户粘贴的回调 URL 完成 bigmodel auth-code 流程。
func (s *ZcodeOAuthService) CompleteBigmodelLogin(ctx context.Context, sessionID, callbackURL string) (*ZcodeLoginStatus, error) {
	session, ok := s.sessionStore.Get(sessionID)
	if !ok {
		return nil, fmt.Errorf("zcode login session not found or expired, restart the login")
	}
	if session.Provider != ZcodeProviderBigmodel {
		return nil, fmt.Errorf("zcode login session is not a paste-mode (bigmodel) session")
	}
	code, err := zcodeParsePastedCallbackURL(callbackURL, session.State)
	if err != nil {
		return nil, err
	}
	s.sessionStore.Delete(sessionID)

	client, err := s.clientFor(ctx, session.ProxyID)
	if err != nil {
		return nil, err
	}
	envelope, err := s.zcodePostJSON(ctx, client, ZcodeTokenEndpoint, "bigmodel token exchange", nil, map[string]string{
		"provider":     ZcodeProviderBigmodel,
		"code":         code,
		"redirect_uri": session.RedirectURI,
		"state":        session.State,
	})
	if err != nil {
		return nil, err
	}
	var data struct {
		Token string `json:"token"`
		User  struct {
			UserID string `json:"user_id"`
		} `json:"user"`
		Bigmodel struct {
			AccessToken string `json:"access_token"`
		} `json:"bigmodel"`
	}
	if err := json.Unmarshal(envelope.Data, &data); err != nil {
		return nil, fmt.Errorf("bigmodel token exchange: invalid response data")
	}
	accessToken := strings.TrimSpace(data.Bigmodel.AccessToken)
	if accessToken == "" {
		return nil, fmt.Errorf("bigmodel token response missing data.bigmodel.access_token")
	}
	credentials, err := s.ResolveCodingPlanCredential(ctx, ZcodeProviderBigmodel, accessToken, data.User.UserID, session.ProxyID)
	if err != nil {
		return nil, err
	}
	if jwt := strings.TrimSpace(data.Token); jwt != "" {
		credentials["jwt"] = jwt
	}
	return &ZcodeLoginStatus{Status: "ready", Credentials: credentials}, nil
}

// zcodeParsePastedCallbackURL 解析用户粘贴的回调 URL（headless 粘贴登录，
// 对齐 zcode-api parsePastedCallbackUrl）：容忍包裹引号/括号/&amp; 实体，
// 校验 CSRF state，返回 authCode。
func zcodeParsePastedCallbackURL(raw, expectedState string) (string, error) {
	text := strings.TrimSpace(raw)
	text = strings.Trim(text, "\"'`<([{")
	text = strings.Trim(text, "\"'`>])}")
	text = strings.ReplaceAll(text, "&amp;", "&")

	query := text
	if idx := strings.Index(text, "?"); idx >= 0 {
		query = text[idx+1:]
	}
	if idx := strings.Index(query, "#"); idx >= 0 {
		query = query[:idx]
	}
	params, err := url.ParseQuery(query)
	if err != nil {
		return "", fmt.Errorf("invalid callback URL: %w", err)
	}
	state := params.Get("state")
	if state == "" || state != expectedState {
		return "", fmt.Errorf("OAuth state mismatch — the pasted URL does not belong to this login session (possible CSRF), retry the login")
	}
	if errCode := params.Get("error"); errCode != "" {
		return "", fmt.Errorf("authorization failed: provider returned error=%s", errCode)
	}
	code := params.Get("authCode")
	if code == "" {
		code = params.Get("code")
	}
	if code == "" {
		return "", fmt.Errorf("no authorization code in the pasted URL — paste the redirected 127.0.0.1 callback URL (the one that failed to load), not the authorize URL")
	}
	return code, nil
}

// ResolveCodingPlanCredential 将 OAuth access_token 解析为 Coding Plan 永久
// API Key（KeyResolver 移植）：
//   - zai：token → api/auth/z/login 换 biz token → customer info → 查找/创建
//     zcode-api-key → 取 secret（凭据串为 apiKey.secret）。
//   - bigmodel：access_token 直接作 biz Bearer → customer info → 查找/创建 Key →
//     secret 合并进完整 Key。
//
// 返回可直接作为 account credentials 的 map。
func (s *ZcodeOAuthService) ResolveCodingPlanCredential(ctx context.Context, provider, accessToken, userID string, proxyID *int64) (map[string]any, error) {
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return nil, fmt.Errorf("empty zcode oauth access token")
	}
	client, err := s.clientFor(ctx, proxyID)
	if err != nil {
		return nil, err
	}

	var bizHost, authorization string
	switch provider {
	case ZcodeProviderZai:
		bizToken, err := s.zaiBizToken(ctx, client, accessToken)
		if err != nil {
			return nil, err
		}
		bizHost = ZcodeZaiHost
		authorization = "Bearer " + bizToken
	default:
		bizHost = ZcodeBigmodelHost
		authorization = accessToken
	}

	orgID, projectID, err := s.resolveCustomerInfo(ctx, client, bizHost, authorization)
	if err != nil {
		return nil, err
	}
	apiKey, err := s.findOrCreateAPIKey(ctx, client, bizHost, authorization, orgID, projectID)
	if err != nil {
		return nil, err
	}
	secret, err := s.getSecretKey(ctx, client, bizHost, authorization, orgID, projectID, apiKey)
	if err != nil {
		// secret 获取失败时退化为仅 apiKey（zcode-api 同语义）。
		secret = ""
	}

	credentials := map[string]any{
		"provider":     provider,
		"api_protocol": APIProtocolAnthropic,
		"plan":         ZcodePlanCoding,
	}
	if provider == ZcodeProviderZai {
		credentials["api_key"] = apiKey
		if secret != "" {
			credentials["secret"] = secret
		}
	} else {
		// bigmodel：secret 在解析阶段合并进完整 Key。
		fullKey := apiKey
		if secret != "" {
			fullKey = apiKey + "." + secret
		}
		credentials["api_key"] = fullKey
	}
	if userID = strings.TrimSpace(userID); userID != "" {
		credentials["user_id"] = userID
	}
	return credentials, nil
}

// zaiBizToken 用 OAuth access_token 换 Z.AI 业务 token。
func (s *ZcodeOAuthService) zaiBizToken(ctx context.Context, client *http.Client, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ZcodeZaiLoginURL,
		bytes.NewReader([]byte(`{"token":"` + jsonStringEscape(accessToken) + `"}`)))
	if err != nil {
		return "", err
	}
	req.Header.Set("content-type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("z/login request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil || resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("z/login failed: status=%d", resp.StatusCode)
	}
	var data struct {
		AccessToken string `json:"access_token"`
		AccessTokenCamel string `json:"accessToken"`
		Data        struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		return "", fmt.Errorf("z/login: invalid response body")
	}
	token := strings.TrimSpace(data.AccessToken)
	if token == "" {
		token = strings.TrimSpace(data.AccessTokenCamel)
	}
	if token == "" {
		token = strings.TrimSpace(data.Data.AccessToken)
	}
	if token == "" {
		return "", fmt.Errorf("z/login returned unexpected shape: access_token missing or empty")
	}
	return token, nil
}

// zcodeCustomerInfo / findOrCreateAPIKey / getSecretKey 对齐 resolver.ts 的 biz API 链。

func (s *ZcodeOAuthService) resolveCustomerInfo(ctx context.Context, client *http.Client, host, authorization string) (string, string, error) {
	data, err := s.bizAPI(ctx, client, http.MethodGet, host+"/api/biz/customer/getCustomerInfo", authorization, nil)
	if err != nil {
		return "", "", err
	}
	const defaultOrgMarker = "默认机构"
	const defaultProjectMarker = "默认项目"

	orgs, _ := data["organizations"].([]any)
	if len(orgs) == 0 {
		orgs, _ = data["orgs"].([]any)
	}
	if len(orgs) == 0 {
		return "", "", fmt.Errorf("no organizations found for zcode account")
	}
	var orgID string
	for _, rawOrg := range orgs {
		org, ok := rawOrg.(map[string]any)
		if !ok {
			continue
		}
		name := zcodeStringField(org, "organizationName", "name")
		if orgID == "" {
			orgID = zcodeStringField(org, "organizationId", "id", "orgId")
		}
		if strings.Contains(name, defaultOrgMarker) {
			orgID = zcodeStringField(org, "organizationId", "id", "orgId")
			break
		}
	}
	if orgID == "" {
		return "", "", fmt.Errorf("no organization id resolved for zcode account")
	}

	var projectID string
	for _, rawOrg := range orgs {
		org, ok := rawOrg.(map[string]any)
		if !ok {
			continue
		}
		id := zcodeStringField(org, "organizationId", "id", "orgId")
		if id != orgID {
			continue
		}
		projects, _ := org["projects"].([]any)
		if len(projects) == 0 {
			return "", "", fmt.Errorf("no projects found in default organization")
		}
		for _, rawProject := range projects {
			project, ok := rawProject.(map[string]any)
			if !ok {
				continue
			}
			name := zcodeStringField(project, "projectName", "name")
			if projectID == "" {
				projectID = zcodeStringField(project, "projectId", "id")
			}
			if strings.Contains(name, defaultProjectMarker) {
				projectID = zcodeStringField(project, "projectId", "id")
				break
			}
		}
		break
	}
	if projectID == "" {
		return "", "", fmt.Errorf("no project id resolved for zcode account")
	}
	return orgID, projectID, nil
}

func (s *ZcodeOAuthService) findOrCreateAPIKey(ctx context.Context, client *http.Client, host, authorization, orgID, projectID string) (string, error) {
	listURL := fmt.Sprintf("%s/api/biz/v1/organization/%s/projects/%s/api_keys", host, url.PathEscape(orgID), url.PathEscape(projectID))

	data, err := s.bizAPI(ctx, client, http.MethodGet, listURL, authorization, nil)
	if err == nil {
		if keys, ok := data["_list"].([]any); ok {
			for _, rawKey := range keys {
				key, ok := rawKey.(map[string]any)
				if !ok {
					continue
				}
				if name := zcodeStringField(key, "name"); name == ZcodeAPIKeyName {
					if apiKey := zcodeStringField(key, "apiKey"); apiKey != "" {
						return apiKey, nil
					}
				}
			}
		}
	}
	// 列表失败视为可创建（resolver.ts 同语义：ignore — will create）。

	created, err := s.bizAPI(ctx, client, http.MethodPost, listURL, authorization, map[string]any{"name": ZcodeAPIKeyName})
	if err != nil {
		return "", err
	}
	apiKey := zcodeStringField(created, "apiKey")
	if apiKey == "" {
		return "", fmt.Errorf("API key creation returned unexpected shape: apiKey missing or empty")
	}
	return apiKey, nil
}

func (s *ZcodeOAuthService) getSecretKey(ctx context.Context, client *http.Client, host, authorization, orgID, projectID, apiKey string) (string, error) {
	target := fmt.Sprintf("%s/api/biz/v1/organization/%s/projects/%s/api_keys/copy/%s",
		host, url.PathEscape(orgID), url.PathEscape(projectID), url.PathEscape(apiKey))
	data, err := s.bizAPI(ctx, client, http.MethodGet, target, authorization, nil)
	if err != nil {
		return "", err
	}
	secret := zcodeStringField(data, "secretKey", "secret_key")
	return secret, nil
}

// bizAPI 调用厂商 biz API 并解包（code 为 0/200/“0”/“200” 视为成功，返回 data 层）。
// 列表端点返回顶层数组，这里包成 {"_list": [...]} 统一处理。
func (s *ZcodeOAuthService) bizAPI(ctx context.Context, client *http.Client, method, target, authorization string, body map[string]any) (map[string]any, error) {
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		payload = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, payload)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("biz API %s failed: %w", target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, fmt.Errorf("biz API %s: read response: %w", target, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("biz API %s failed: status=%d body=%s", target, resp.StatusCode, truncateZcodeBody(raw))
	}

	var topLevel any
	if err := json.Unmarshal(raw, &topLevel); err != nil {
		return nil, fmt.Errorf("biz API %s: invalid JSON body", target)
	}
	if list, ok := topLevel.([]any); ok {
		return map[string]any{"_list": list}, nil
	}
	obj, ok := topLevel.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("biz API %s: unexpected response shape", target)
	}
	code, hasCode := obj["code"]
	if !hasCode {
		if status, ok := obj["status"]; ok {
			code = status
			hasCode = true
		}
	}
	if hasCode {
		switch v := code.(type) {
		case float64:
			if v != 0 && v != 200 {
				msg, _ := obj["msg"].(string)
				return nil, fmt.Errorf("biz API %s error %v: %s", target, v, msg)
			}
		case string:
			if v != "0" && v != "200" {
				msg, _ := obj["msg"].(string)
				return nil, fmt.Errorf("biz API %s error %s: %s", target, v, msg)
			}
		}
	}
	if data, ok := obj["data"].(map[string]any); ok {
		return data, nil
	}
	return obj, nil
}

// BuildZcodeAccountCredentials 在 OAuth 凭证基础上补充账号创建所需的固定维度。
func BuildZcodeAccountCredentials(credentials map[string]any) map[string]any {
	credentials["api_protocol"] = APIProtocolAnthropic
	if _, ok := credentials["plan"]; !ok {
		credentials["plan"] = ZcodePlanCoding
	}
	return credentials
}

func zcodeStringField(obj map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, ok := obj[key].(string); ok {
			if trimmed := strings.TrimSpace(v); trimmed != "" {
				return trimmed
			}
		}
	}
	return ""
}

func jsonStringEscape(s string) string {
	encoded, err := json.Marshal(s)
	if err != nil {
		return ""
	}
	return string(encoded[1 : len(encoded)-1])
}

func zcodeRandomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
