//go:build unit

package service

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// zcodeAccountTestAccount 构造 Start Plan（trial）ZCode 账号：仅 JWT 鉴权，
// 走 zcode.z.ai 网关（与线上 "captcha verify failed" 事故场景一致）。
func zcodeAccountTestAccount(id int64) *Account {
	return &Account{
		ID:          id,
		Name:        "zcode-test",
		Platform:    PlatformZcode,
		Type:        AccountTypeAPIKey,
		Status:      StatusActive,
		Concurrency: 1,
		Credentials: map[string]any{
			"provider":     ZcodeProviderZai,
			"plan":         ZcodePlanStart,
			"jwt":          "plan-jwt-token",
			"api_key":      "zkey",
			"secret":       "zsec",
			"device_mid":   "dev-mid-1",
			"api_protocol": APIProtocolAnthropic,
		},
	}
}

func zcodeAccountTestService(account *Account) (*AccountTestService, *httpUpstreamRecorder) {
	repo := &openAIAccountTestRepo{
		mockAccountRepoForGemini: mockAccountRepoForGemini{
			accountsByID: map[int64]*Account{account.ID: account},
		},
	}
	upstream := &httpUpstreamRecorder{responses: []*http.Response{adaptiveCNAnthropicTestResponse()}}
	return &AccountTestService{
		accountRepo:  repo,
		httpUpstream: upstream,
		cfg:          rawChatCompletionsTestConfig(),
	}, upstream
}

// ZCode 测试探针必须与真实转发路径（forwardAnthropicViaNativeAnthropicEndpoint）
// 一样对 body 应用 ApplyZcodeBodyTransform。曾遗漏该变换：探针携带 Claude Code
// 风格的 UUID metadata.user_id，与请求上的 ZCode 身份指纹互相矛盾，zcode.z.ai
// 网关风控以 400 {"code":3007,"msg":"captcha verify failed"} 拒绝，账号测试永远失败。
func TestAccountTestService_ZcodeProbeAppliesOfficialClientBodyTransform(t *testing.T) {
	account := zcodeAccountTestAccount(401)
	svc, upstream := zcodeAccountTestService(account)
	c, recorder := newTestContext()

	err := svc.TestAccountConnection(c, account.ID, "glm-5.3-flash", "", AccountTestModeDefault)

	require.NoError(t, err)
	require.Contains(t, recorder.Body.String(), `"type":"test_complete"`)
	require.Len(t, upstream.requests, 1)
	req, body := upstream.requests[0], upstream.bodies[0]

	// trial 计划走 zcode 网关 + JWT Bearer（无 x-api-key）
	require.Equal(t, ZcodeStartPlanAnthropicBaseURL+"/v1/messages", req.URL.String())
	require.Equal(t, "Bearer plan-jwt-token", req.Header.Get("Authorization"))
	require.Empty(t, req.Header.Get("x-api-key"))
	require.Equal(t, "glm-5.3-flash", gjson.GetBytes(body, "model").String())

	// metadata.user_id 必须是 ZCode 设备/会话 blob，而非探针的 UUID 串
	userID := gjson.GetBytes(body, "metadata.user_id").String()
	require.True(t, gjson.Valid(userID), "metadata.user_id must be a JSON blob, got %q", userID)
	require.Equal(t, "dev-mid-1", gjson.Get(userID, "device_id").String())
	require.Empty(t, gjson.Get(userID, "account_uuid").String())
}
