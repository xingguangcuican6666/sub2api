//go:build unit

package service

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

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
	// 账号为试用套餐但本测试聚焦 body 变换：禁用验证码管理器避免真实取 token。
	zcodeCaptchaSetManagerForTest(t, func(m *zcodeCaptchaManager) { m.state = zcodeCaptchaDisabled })

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

// 验证码管理器可用时，探针必须为试用套餐请求附加阿里云验证码头。
func TestAccountTestService_ZcodeProbeAttachesCaptchaToken(t *testing.T) {
	zcodeCaptchaSetManagerForTest(t, func(m *zcodeCaptchaManager) {
		*m = *zcodeCaptchaRunningManager(t, &fakeZcodeCaptchaSolver{}, zcodeCaptchaToken{
			VerifyParam: zcodeCaptchaValidToken(), Region: "cn", expiresAt: time.Now().Add(time.Minute),
		})
	})

	account := zcodeAccountTestAccount(402)
	svc, upstream := zcodeAccountTestService(account)
	c, _ := newTestContext()

	err := svc.TestAccountConnection(c, account.ID, "glm-5.3-flash", "", AccountTestModeDefault)

	require.NoError(t, err)
	require.Len(t, upstream.requests, 1)
	req := upstream.requests[0]
	require.Equal(t, zcodeCaptchaValidToken(), req.Header.Get(ZcodeCaptchaParamHeader))
	require.Equal(t, "cn", req.Header.Get(ZcodeCaptchaRegionHeader))
}

// 上游返回 3007 风控挑战时：补解 token 并整请求重试一次，重试成功则整体成功。
func TestAccountTestService_ZcodeProbeRetriesOnCaptchaChallenge(t *testing.T) {
	zcodeCaptchaSetManagerForTest(t, func(m *zcodeCaptchaManager) {
		*m = *zcodeCaptchaRunningManager(t, &fakeZcodeCaptchaSolver{params: []string{zcodeCaptchaValidToken()}},
			zcodeCaptchaToken{VerifyParam: "stale-token", Region: "cn", expiresAt: time.Now().Add(time.Minute)})
	})

	account := zcodeAccountTestAccount(403)
	svc, upstream := zcodeAccountTestService(account)
	// 第一次响应 3007 挑战，第二次放行。
	upstream.responses = []*http.Response{zcodeCaptchaChallengeResponse(), adaptiveCNAnthropicTestResponse()}
	c, recorder := newTestContext()

	err := svc.TestAccountConnection(c, account.ID, "glm-5.3-flash", "", AccountTestModeDefault)

	require.NoError(t, err)
	require.Contains(t, recorder.Body.String(), `"type":"test_complete"`)
	require.Len(t, upstream.requests, 2)
	require.Equal(t, "stale-token", upstream.requests[0].Header.Get(ZcodeCaptchaParamHeader))
	require.Equal(t, zcodeCaptchaValidToken(), upstream.requests[1].Header.Get(ZcodeCaptchaParamHeader))
}

// 求解器不可用且上游 3007：探针失败并给出可操作的中文提示。
func TestAccountTestService_ZcodeProbeSurfacesCaptchaHint(t *testing.T) {
	zcodeCaptchaSetManagerForTest(t, func(m *zcodeCaptchaManager) {
		m.state = zcodeCaptchaUnavailable
		m.reason = "no chrome installed"
	})

	account := zcodeAccountTestAccount(404)
	svc, upstream := zcodeAccountTestService(account)
	upstream.responses = []*http.Response{zcodeCaptchaChallengeResponse()}
	c, recorder := newTestContext()

	err := svc.TestAccountConnection(c, account.ID, "glm-5.3-flash", "", AccountTestModeDefault)

	require.Error(t, err)
	require.Len(t, upstream.requests, 1, "求解器不可用时不应盲目重试")
	require.Contains(t, recorder.Body.String(), "3007")
	require.Contains(t, recorder.Body.String(), "阿里云验证码")
	require.Contains(t, recorder.Body.String(), "no chrome installed")
}

func zcodeCaptchaChallengeResponse() *http.Response {
	return &http.Response{
		StatusCode: http.StatusBadRequest,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"code":3007,"msg":"captcha verify failed"}`)),
	}
}
