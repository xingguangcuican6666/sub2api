package service

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func mkZcodeAccount(provider, plan string) *Account {
	return &Account{
		Platform: PlatformZcode,
		Type:     AccountTypeAPIKey,
		Credentials: map[string]any{
			"provider":     provider,
			"plan":         plan,
			"api_key":      "key123",
			"secret":       "sec456",
			"jwt":          "jwt-token",
			"user_id":      "u-1",
			"device_mid":   "dev-mid-1",
			"api_protocol": APIProtocolAnthropic,
		},
	}
}

func TestZcodeGetAPIProtocolIsAlwaysAnthropic(t *testing.T) {
	for _, provider := range []string{ZcodeProviderZai, ZcodeProviderBigmodel} {
		for _, plan := range []string{ZcodePlanCoding, ZcodePlanStart, ZcodePlanGlobalBuild, ZcodePlanWeekend} {
			account := mkZcodeAccount(provider, plan)
			require.Equal(t, APIProtocolAnthropic, account.GetAPIProtocol())
			require.True(t, account.IsAnthropicProtocol())
			require.True(t, account.IsZcode())
			require.True(t, IsMultiProtocolAPIKeyProvider(PlatformZcode))
		}
	}
}

func TestZcodeAnthropicBaseURL(t *testing.T) {
	require.Equal(t, DefaultZcodeZaiAnthropicBaseURL, mkZcodeAccount(ZcodeProviderZai, ZcodePlanCoding).GetZcodeAnthropicBaseURL())
	require.Equal(t, DefaultZcodeBigmodelAnthropicBaseURL, mkZcodeAccount(ZcodeProviderBigmodel, ZcodePlanCoding).GetZcodeAnthropicBaseURL())
	// 试用/活动套餐（start-plan / global-build / weekend）固定走 zcode.z.ai 网关，
	// 忽略 provider 与自定义 base_url。
	for _, plan := range []string{ZcodePlanStart, ZcodePlanGlobalBuild, ZcodePlanWeekend} {
		trial := mkZcodeAccount(ZcodeProviderZai, plan)
		trial.Credentials["base_url"] = "https://relay.example.com/anthropic"
		require.Equal(t, ZcodeStartPlanAnthropicBaseURL, trial.GetZcodeAnthropicBaseURL())
		require.True(t, IsZcodeTrialPlan(plan))
	}
	require.False(t, IsZcodeTrialPlan(ZcodePlanCoding))
	// coding-plan 支持自定义中转 base_url。
	custom := mkZcodeAccount(ZcodeProviderZai, ZcodePlanCoding)
	custom.Credentials["base_url"] = "https://relay.example.com/anthropic/"
	require.Equal(t, "https://relay.example.com/anthropic/", custom.GetZcodeAnthropicBaseURL())
}

func TestZcodeCredentialString(t *testing.T) {
	require.Equal(t, "key123.sec456", mkZcodeAccount(ZcodeProviderZai, ZcodePlanCoding).ZcodeCredentialString())
	bigmodel := mkZcodeAccount(ZcodeProviderBigmodel, ZcodePlanCoding)
	// bigmodel 在解析阶段已合并 secret；凭据串不重复拼接。
	bigmodel.Credentials["api_key"] = "key123.sec456"
	bigmodel.Credentials["secret"] = ""
	require.Equal(t, "key123.sec456", bigmodel.ZcodeCredentialString())
}

func TestZcodeIdentityHeaders(t *testing.T) {
	llm := BuildZcodeLLMIdentityHeaders(mkZcodeAccount(ZcodeProviderZai, ZcodePlanCoding))
	require.Equal(t, "ZCode/"+ZcodeAppVersionDefault, llm["User-Agent"])
	require.Equal(t, ZcodeAgentHeader, llm["X-ZCode-Agent"])
	require.Equal(t, "Z Code@cli", llm["X-Title"])
	require.Equal(t, "linux-x64", llm["X-Platform"])
	require.Equal(t, "linux", llm["X-Os-Category"])
	require.NotContains(t, llm, "X-Device-Mid")

	control := BuildZcodeControlPlaneIdentityHeaders(mkZcodeAccount(ZcodeProviderZai, ZcodePlanCoding))
	require.Equal(t, "dev-mid-1", control["X-Device-Mid"])
}

func TestApplyZcodeBodyTransform(t *testing.T) {
	account := mkZcodeAccount(ZcodeProviderZai, ZcodePlanCoding)
	body := []byte(`{"model":"glm-5.3","messages":[
		{"role":"user","content":[{"type":"text","text":"hi","cache_control":{"type":"ephemeral"}}]},
		{"role":"assistant","content":"hello"},
		{"role":"user","content":"again"}]}`)

	out := ApplyZcodeBodyTransform(body, account)

	// 旧标记被清除，仅最后一条非 system 消息携带 marker。
	require.False(t, gjson.GetBytes(out, "messages.0.content.0.cache_control").Exists())
	require.True(t, gjson.GetBytes(out, "messages.2.content.0.cache_control").Exists())
	require.Equal(t, "ephemeral", gjson.GetBytes(out, "messages.2.content.0.cache_control.type").String())
	// metadata.user_id 注入为 device/session blob。
	var metadata struct {
		UserID string `json:"user_id"`
	}
	require.NoError(t, json.Unmarshal([]byte(gjson.GetBytes(out, "metadata").Raw), &metadata))
	require.NotEmpty(t, metadata.UserID)
}

func TestZcodeMetadataUserID(t *testing.T) {
	require.JSONEq(t, `{"device_id":"dev-mid-1","account_uuid":"","session_id":""}`, BuildZcodeMetadataUserID("dev-mid-1"))
	// device_mid 缺失时省略 device_id（对齐 JSON.stringify 的 undefined 行为）。
	require.JSONEq(t, `{"account_uuid":"","session_id":""}`, BuildZcodeMetadataUserID(""))
}

func TestZcodeParsePastedCallbackURL(t *testing.T) {
	code, err := zcodeParsePastedCallbackURL(
		`"http://127.0.0.1:62156/oauth/callback/bigmodel?authCode=abc123&state=st1&amp;x=1"`, "st1")
	require.NoError(t, err)
	require.Equal(t, "abc123", code)

	// state 不匹配 → CSRF 拒绝。
	_, err = zcodeParsePastedCallbackURL("http://127.0.0.1/cb?authCode=abc&state=other", "st1")
	require.Error(t, err)

	// 缺 authCode → 报错。
	_, err = zcodeParsePastedCallbackURL("http://127.0.0.1/cb?state=st1", "st1")
	require.Error(t, err)
}

func TestZcodeMachineQuotaTiers(t *testing.T) {
	tiers := []CNQuotaTier{
		{Window: "提示词", UsedPercent: 20},
		{Window: "额度包", UsedPercent: 80},
		{Window: "赠送", UsedPercent: 50},
	}
	machine := zcodeMachineQuotaTiers(tiers)
	require.Len(t, machine, 2)
	require.Equal(t, "5h", machine[0].Window)
	require.Equal(t, float64(80), machine[0].UsedPercent)
	require.Equal(t, "weekly", machine[1].Window)
	require.Equal(t, float64(50), machine[1].UsedPercent)

	updates := cnQuotaExtraUpdates(PlatformZcode, machine, time.Now().UTC())
	require.Contains(t, updates, cnExtraKey(PlatformZcode, cnExtraSuffix5hUsed))
	require.Contains(t, updates, cnExtraKey(PlatformZcode, cnExtraSuffixWeeklyUsed))
}

func TestZcodeDefaultModelIDs(t *testing.T) {
	models := DefaultZcodeModelIDs()
	require.NotEmpty(t, models)
	require.Contains(t, models, "glm-5.3")
	require.Contains(t, models, "glm-5.3-flash")
}
