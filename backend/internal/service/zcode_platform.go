package service

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/tidwall/sjson"
)

// ZCode 平台出站伪装与 body 规范化（对齐 TriDefender/zcode-api 的
// identity.ts / trace-headers.ts / body-transformer.ts，逆向自 ZCode 3.11.2 桌面端）。
//
// ZCode 上游统一为 Anthropic 兼容协议，出站请求需要携带 ZCode 桌面客户端的
// 身份指纹头（identity headers）、归因头（trace headers）与 metadata.user_id，
// 并对 body 做 cache_control 标记，使流量与官方客户端不可区分。

var zcodePrintableASCIIRune = func(r rune) bool {
	return r >= 0x20 && r <= 0x7e
}

// DefaultZcodeModelIDs 是 ZCode GLM Coding Plan 公开的模型 ID 目录
// （对齐 zcode-api 的模型清单），供 /v1/models 在尚未同步上游列表时回退，
// 以及账号模型白名单预填。
// DefaultZcodeTestModel 是账号连通性测试使用的默认 GLM 模型。
const DefaultZcodeTestModel = "glm-5.3"

func DefaultZcodeModelIDs() []string {
	return []string{
		"glm-4.5-air",
		"glm-4.6",
		"glm-4.6v",
		"glm-4.7",
		"glm-5",
		"glm-5-turbo",
		"glm-5v-turbo",
		"glm-5.1",
		"glm-5.2",
		"glm-5.3",
		"glm-5.3-flash",
	}
}

// zcodeNormalizeHeaderValue 校验 header 值为非空可打印 ASCII（对齐 bundle `fio`），
// 不合规返回空串（调用方据此省略该 header）。
func zcodeNormalizeHeaderValue(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return ""
	}
	for _, r := range v {
		if !zcodePrintableASCIIRune(r) {
			return ""
		}
	}
	return v
}

// zcodeNormalizeOsCategory 将 platform 归一为 ZCode 客户端的 os category。
func zcodeNormalizeOsCategory(platform string) string {
	switch platform {
	case "darwin":
		return "macos"
	case "windows":
		return "windows"
	default:
		return "linux"
	}
}

// zcodeResolveIdentityValues 解析身份指纹的运行时取值。server 版无桌面环境，
// 固定输出 linux-x64 桌面指纹（与 zcode-api 的 ZCODE_IDENTITY_* 覆盖语义一致）。
func zcodeResolveIdentityValues(account *Account) (appVersion, platform, arch, release, deviceMid string) {
	appVersion = ZcodeAppVersionDefault
	if account != nil {
		if v := zcodeNormalizeHeaderValue(account.GetCredential("identity_app_version")); v != "" {
			appVersion = v
		}
		deviceMid = zcodeNormalizeHeaderValue(account.GetCredential("device_mid"))
	}
	platform = "linux"
	arch = "x64"
	release = ""
	return
}

// BuildZcodeLLMIdentityHeaders 构造 LLM 请求的身份指纹头（bundle `csn` + `x4i`）：
// HTTP-Referer、User-Agent、X-ZCode-App-Version、X-Title、X-Release-Channel、
// X-Client-Language/Timezone（unknown 兜底）、X-Platform、X-Os-Category、
// X-Os-Version，最后是 X-ZCode-Agent。LLM 路径不携带 X-Device-Mid。
func BuildZcodeLLMIdentityHeaders(account *Account) map[string]string {
	appVersion, platform, arch, release, _ := zcodeResolveIdentityValues(account)
	headers := map[string]string{
		"HTTP-Referer":        ZcodeRefererOrigin,
		"User-Agent":          ZcodeUserAgentPrefix + appVersion,
		"X-Title":             "Z Code@cli",
		"X-Release-Channel":   "production",
		"X-Client-Language":   "unknown",
		"X-Client-Timezone":   "unknown",
		"X-ZCode-Agent":       ZcodeAgentHeader,
		"X-ZCode-App-Version": appVersion,
	}
	if platform != "" && arch != "" {
		headers["X-Platform"] = platform + "-" + arch
	}
	if platform != "" {
		headers["X-Os-Category"] = zcodeNormalizeOsCategory(platform)
	}
	if release != "" {
		headers["X-Os-Version"] = release
	}
	return headers
}

// BuildZcodeControlPlaneIdentityHeaders 构造控制面请求（OAuth、账单额度）的身份头
// （bundle `HRt`）：与 LLM 集合的差异是携带 X-Device-Mid、语言/时区条件输出、
// X-ZCode-Agent 位置不同。zcode.z.ai 账单网关要求稳定 X-Device-Mid。
func BuildZcodeControlPlaneIdentityHeaders(account *Account) map[string]string {
	appVersion, platform, arch, release, deviceMid := zcodeResolveIdentityValues(account)
	headers := map[string]string{
		"HTTP-Referer":        ZcodeRefererOrigin,
		"User-Agent":          ZcodeUserAgentPrefix + appVersion,
		"X-ZCode-Agent":       ZcodeAgentHeader,
		"X-ZCode-App-Version": appVersion,
		"X-Title":             "Z Code@cli",
		"X-Release-Channel":   "production",
	}
	if platform != "" && arch != "" {
		headers["X-Platform"] = platform + "-" + arch
	}
	if platform != "" {
		headers["X-Os-Category"] = zcodeNormalizeOsCategory(platform)
	}
	if release != "" {
		headers["X-Os-Version"] = release
	}
	if deviceMid != "" {
		headers["X-Device-Mid"] = deviceMid
	}
	return headers
}

// zcodeRandomUUID 生成 RFC4122 v4 随机 UUID（trace 头用）。
func zcodeRandomUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000-0000-4000-8000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	dst := make([]byte, 36)
	hex.Encode(dst, b[:4])
	dst[8] = '-'
	hex.Encode(dst[9:13], b[4:6])
	dst[13] = '-'
	hex.Encode(dst[14:18], b[6:8])
	dst[18] = '-'
	hex.Encode(dst[19:23], b[8:10])
	dst[23] = '-'
	hex.Encode(dst[24:], b[10:16])
	return string(dst)
}

// zcodeStripSessionPrefixes 剥离客户端会话 ID 的内部前缀（sess_ / subagent_agent_），
// 对齐 bundle `bnt`/`NIo`/`LIo`。
func zcodeStripSessionPrefixes(value string) string {
	for _, prefix := range []string{"sess_", "subagent_agent_"} {
		if strings.HasPrefix(value, prefix) && len(value) > len(prefix) {
			return value[len(prefix):]
		}
	}
	return value
}

// BuildZcodeTraceHeaders 构造归因头（bundle `Bdt` createModelRequestAttributionHeaders）：
// x-request-id、x-zcode-session-type、x-zcode-trace-id、[x-query-id]、[x-session-id]。
// coding-plan 才带 query/session 归因；start-plan 与官方客户端一致不携带。
func BuildZcodeTraceHeaders(plan string) map[string]string {
	headers := map[string]string{
		"x-request-id":         zcodeRandomUUID(),
		"x-zcode-session-type": "main",
		"x-zcode-trace-id":     zcodeRandomUUID(),
	}
	if plan != ZcodePlanStart {
		headers["x-query-id"] = zcodeRandomUUID()
		headers["x-session-id"] = zcodeRandomUUID()
	}
	return headers
}

// ApplyZcodeUpstreamHeaders 注入 ZCode 上游请求的认证、身份指纹与归因头。
//   - coding-plan：x-api-key 与 Authorization: Bearer 双头同值（bundle `ebo`），
//     User-Agent 追加 ai-sdk/anthropic SDK 后缀（bundle `Cm`/k0o）。
//   - start-plan：Authorization: Bearer {jwt}（plan JWT）。
func ApplyZcodeUpstreamHeaders(header http.Header, account *Account) error {
	plan := account.GetZcodePlan()
	var credential string
	switch plan {
	case ZcodePlanStart:
		credential = account.GetZcodeJWT()
		if credential == "" {
			return fmt.Errorf("zcode start-plan account missing jwt, re-run OAuth login")
		}
	default:
		credential = account.ZcodeCredentialString()
		if credential == "" {
			return fmt.Errorf("zcode account missing api_key")
		}
	}
	identity := BuildZcodeLLMIdentityHeaders(account)
	for key, value := range identity {
		header.Set(key, value)
	}
	// LLM 请求的 UA 携带 anthropic SDK 后缀（与官方客户端一致）。
	header.Set("User-Agent", identity["User-Agent"]+" "+ZcodeAnthropicSDKUA)
	if plan != ZcodePlanStart {
		header.Set("x-api-key", credential)
	}
	header.Set("authorization", "Bearer "+credential)
	header.Set("anthropic-version", "2023-06-01")
	for key, value := range BuildZcodeTraceHeaders(plan) {
		header.Set(key, value)
	}
	return nil
}

// BuildZcodeMetadataUserID 构造 Anthropic body 的 metadata.user_id
// （bundle `E2e`/`UIo`）：{"device_id":..,"account_uuid":"","session_id":..}。
// account_uuid 恒为空串（官方客户端硬编码）；device_mid 缺失时省略 device_id
// （对齐 JSON.stringify 对 undefined 值的处理）。
func BuildZcodeMetadataUserID(deviceMid string) string {
	payload := struct {
		DeviceID    string `json:"device_id,omitempty"`
		AccountUUID string `json:"account_uuid"`
		SessionID   string `json:"session_id"`
	}{
		DeviceID:    deviceMid,
		AccountUUID: "",
		SessionID:   "",
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return `{"account_uuid":"","session_id":""}`
	}
	return string(b)
}

// ApplyZcodeBodyTransform 对发往 ZCode 上游的 Anthropic body 做官方客户端等价变换：
//  1. 清除非 system 消息的 cache_control，再为最后一条非 system 消息的最后一个
//     content block 加 {type: "ephemeral"}（bundle `zsi`+`Fsi`，applyCacheControl 默认开启）；
//  2. 注入 metadata.user_id（bundle `E2e` 对所有 anthropic 请求触发；值是
//     device/session blob，官方流量从不携带账号 uuid）。
//
// 变换在 JSON 层完成，解析失败或无改动时返回原 body。
func ApplyZcodeBodyTransform(body []byte, account *Account) []byte {
	if len(body) == 0 {
		return body
	}
	updated := body
	if patched := applyZcodeCacheControl(body); patched != nil {
		updated = patched
	}
	deviceMid := ""
	if account != nil {
		deviceMid = account.GetCredential("device_mid")
	}
	injected, err := sjson.SetBytes(updated, "metadata.user_id", BuildZcodeMetadataUserID(deviceMid))
	if err != nil {
		return updated
	}
	return injected
}

// applyZcodeCacheControl 移植 body-transformer.ts 的 applyAnthropicCacheControl：
// 两阶段 cache_control 注入。返回 nil 表示无需改动。
func applyZcodeCacheControl(body []byte) []byte {
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil
	}
	rawMessages, ok := parsed["messages"].([]any)
	if !ok || len(rawMessages) == 0 {
		return nil
	}

	cleaned := false
	for _, rawMsg := range rawMessages {
		msg, ok := rawMsg.(map[string]any)
		if !ok || msg["role"] == "system" {
			continue
		}
		blocks, ok := msg["content"].([]any)
		if !ok {
			continue
		}
		for _, rawBlock := range blocks {
			block, ok := rawBlock.(map[string]any)
			if !ok {
				continue
			}
			if _, exists := block["cache_control"]; exists {
				delete(block, "cache_control")
				cleaned = true
			}
		}
	}

	marked := false
	for i := len(rawMessages) - 1; i >= 0; i-- {
		msg, ok := rawMessages[i].(map[string]any)
		if !ok || msg["role"] == "system" {
			continue
		}
		switch content := msg["content"].(type) {
		case string:
			msg["content"] = []map[string]any{{
				"type":          "text",
				"text":          content,
				"cache_control": map[string]string{"type": "ephemeral"},
			}}
			marked = true
		case []any:
			if len(content) > 0 {
				if lastBlock, ok := content[len(content)-1].(map[string]any); ok {
					if _, exists := lastBlock["cache_control"]; !exists {
						lastBlock["cache_control"] = map[string]string{"type": "ephemeral"}
						marked = true
					}
				}
			}
		}
		break
	}

	if !cleaned && !marked {
		return nil
	}
	out, err := json.Marshal(parsed)
	if err != nil {
		return nil
	}
	return out
}
