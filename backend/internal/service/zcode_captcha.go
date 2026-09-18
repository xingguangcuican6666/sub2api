package service

// ZCode（Start Plan 等试用套餐）阿里云验证码对抗。
//
// zcode.z.ai 网关对试用套餐的 LLM 请求强制要求阿里云验证码 token：请求需携带
// x-aliyun-captcha-verify-param / x-aliyun-captcha-verify-region 两个头，缺失或
// 无效时上游返回 400/403 {"code":3007,"msg":"captcha verify failed"}（挑战也会以
// 响应头 x-aliyun-captcha-verify-param 的形式下发）。Coding Plan（API Key 直连
// api.z.ai）不需要验证码。
//
// 机制对齐 TriDefender/zcode-api 的 proxy/captcha*.ts：
//   - 场景配置从 {ZcodeAPIBase}/client/configs 拉取（enabled/prefix/sceneId/region）；
//   - 无痕验证（startTracelessVerification）由本机 headless Chrome 自动完成，
//     无需人工交互，产出的 verifyParam 为一次性、约 95s 过期的 base64 JSON；
//   - token 由后台池预热，热路径取现成 token；遇挑战急速补解并整请求重试一次。
//
// 已知限制：求解走宿主机网络（不带账号代理），若账号配置了出口代理，token 的
// IP 与请求 IP 不一致时风控可能仍拒绝。

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/httpclient"
)

const (
	// ZcodeCaptchaParamHeader / ZcodeCaptchaRegionHeader 是上游验证码头。
	ZcodeCaptchaParamHeader  = "x-aliyun-captcha-verify-param"
	ZcodeCaptchaRegionHeader = "x-aliyun-captcha-verify-region"

	zcodeCaptchaConfigTTL  = 5 * time.Minute
	zcodeCaptchaTokenTTL   = 80 * time.Second // 上游 ~95s 过期，提前丢弃
	zcodeCaptchaPoolMin    = 2
	zcodeCaptchaPoolMax    = 10
	zcodeCaptchaMaxSolving = 2 // 并发求解上限（每解占一个浏览器页）
	zcodeCaptchaTakeWait   = 25 * time.Second
	zcodeCaptchaSolveWait  = 30 * time.Second
)

// ZcodeCaptchaConfig 是 client/configs 下发的验证码场景配置。
type ZcodeCaptchaConfig struct {
	Enabled bool   `json:"enabled"`
	Prefix  string `json:"prefix"`
	SceneID string `json:"sceneId"`
	Region  string `json:"region"`
}

type zcodeCaptchaToken struct {
	VerifyParam string
	Region      string
	expiresAt   time.Time
}

func (t *zcodeCaptchaToken) valid() bool { return t != nil && time.Now().Before(t.expiresAt) }

// setZcodeCaptchaHeaders 把 token 写入出站请求头。
func setZcodeCaptchaHeaders(header http.Header, token *zcodeCaptchaToken) {
	if token == nil {
		return
	}
	header.Set(ZcodeCaptchaParamHeader, token.VerifyParam)
	header.Set(ZcodeCaptchaRegionHeader, token.Region)
}

// zcodeCaptchaChallengeFromHeader 返回挑战响应头中的 verify param（无则空串）。
func zcodeCaptchaChallengeFromHeader(header http.Header) string {
	return strings.TrimSpace(header.Get(ZcodeCaptchaParamHeader))
}

// zcodeCaptchaIsInBodyChallenge 检测响应体内嵌的 3007 挑战（无挑战头变体）。
func zcodeCaptchaIsInBodyChallenge(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	return strings.Contains(string(body), `"code":3007`) || strings.Contains(string(body), `"code": 3007`)
}

// zcodeCaptchaChallenge 统一挑战判定：响应头变体优先，其次 body 内 3007。
func zcodeCaptchaChallenge(header http.Header, body []byte) bool {
	return zcodeCaptchaChallengeFromHeader(header) != "" || zcodeCaptchaIsInBodyChallenge(body)
}

// zcodeValidateVerifyParam 校验求解产物的真实形态：一个 ~280 字符的 base64 JSON，
// 含 certifyId + sceneId + isSign + 长 securityToken。短于 200 字符或缺
// securityToken 的是 SDK 降级产物，发出必 3007（对齐 captcha-happy.ts
// extractVerifyParam 的严格校验）。
func zcodeValidateVerifyParam(param string) (string, error) {
	param = strings.TrimSpace(param)
	if len(param) < 200 {
		return "", fmt.Errorf("captcha verify param too short (%d chars) — degraded result", len(param))
	}
	decoded, err := base64.StdEncoding.DecodeString(param)
	if err != nil {
		// 阿里云可能使用 URL-safe 变体。
		decoded, err = base64.URLEncoding.DecodeString(param)
		if err != nil {
			return "", fmt.Errorf("captcha verify param not base64: %w", err)
		}
	}
	var payload struct {
		SecurityToken string `json:"securityToken"`
	}
	if err := json.Unmarshal(decoded, &payload); err != nil || len(payload.SecurityToken) < 50 {
		return "", fmt.Errorf("captcha verify param missing securityToken — degraded result")
	}
	return param, nil
}

// ── 场景配置 ─────────────────────────────────────────────────────────────────

func fetchZcodeCaptchaConfig(ctx context.Context) (*ZcodeCaptchaConfig, error) {
	client, err := httpclient.GetClient(httpclient.Options{Timeout: 15 * time.Second})
	if err != nil {
		client = http.DefaultClient
	}
	target := fmt.Sprintf("%s/client/configs?app_version=%s&platform=win32-x64",
		ZcodeAPIBase, url.QueryEscape(ZcodeAppVersionDefault))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch captcha config: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return nil, fmt.Errorf("read captcha config: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch captcha config: status=%d", resp.StatusCode)
	}
	var envelope struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			Configs struct {
				Captcha *ZcodeCaptchaConfig `json:"captcha"`
			} `json:"configs"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("captcha config: invalid JSON body")
	}
	if envelope.Code != 0 || envelope.Data.Configs.Captcha == nil {
		return nil, fmt.Errorf("captcha config unavailable (code=%d msg=%s)", envelope.Code, envelope.Msg)
	}
	return envelope.Data.Configs.Captcha, nil
}

// ── token 池 ─────────────────────────────────────────────────────────────────

type zcodeCaptchaPool struct {
	mu        sync.Mutex
	tokens    []zcodeCaptchaToken // FIFO（先到期先出）
	solving   int
	kick      bool
	lastErr   string
	lastErrAt time.Time
	signal    chan struct{} // 有新 token / 状态变化时关闭重建，唤醒等待者
}

func newZcodeCaptchaPool() *zcodeCaptchaPool {
	return &zcodeCaptchaPool{signal: make(chan struct{})}
}

func (p *zcodeCaptchaPool) broadcastLocked() {
	close(p.signal)
	p.signal = make(chan struct{})
}

// take 取一个有效 token；池空时等待在途/紧急补解。求解失败且无在途解时
// 快速失败（避免每个请求都干等超时）。
func (p *zcodeCaptchaPool) take(ctx context.Context) (*zcodeCaptchaToken, error) {
	deadline := time.Now().Add(zcodeCaptchaTakeWait)
	for {
		p.mu.Lock()
		p.dropExpiredLocked()
		if len(p.tokens) > 0 {
			tok := p.tokens[0]
			p.tokens = p.tokens[1:]
			p.mu.Unlock()
			return &tok, nil
		}
		if p.solving == 0 {
			if !p.lastErrAt.IsZero() && time.Since(p.lastErrAt) < 5*time.Second && !p.kick {
				err := fmt.Errorf("captcha solver failed: %s", p.lastErr)
				p.mu.Unlock()
				return nil, err
			}
			p.kick = true
		}
		signal := p.signal
		p.mu.Unlock()

		wait := time.Until(deadline)
		if wait > 0 {
			var cancel context.CancelFunc
			if _, hasDeadline := ctx.Deadline(); !hasDeadline {
				ctx, cancel = context.WithTimeout(ctx, wait)
				defer cancel()
			}
			select {
			case <-signal:
				continue
			case <-ctx.Done():
				return nil, fmt.Errorf("captcha token wait timeout: %w", ctx.Err())
			}
		}
		return nil, fmt.Errorf("captcha token wait timeout")
	}
}

func (p *zcodeCaptchaPool) dropExpiredLocked() {
	kept := p.tokens[:0]
	for _, tok := range p.tokens {
		if tok.valid() {
			kept = append(kept, tok)
		}
	}
	p.tokens = kept
}

// zcodeCaptchaRefillInterval 池补解轮询间隔（测试中可调小）。
var zcodeCaptchaRefillInterval = 3 * time.Second

// refillLoop 后台补解：池低于下限或有人紧急催解时调度求解（受并发上限约束）。
// 启动时立即检查一次（消除冷启动的定时器空等），进程生命周期内常驻。
func (p *zcodeCaptchaPool) refillLoop(ctx context.Context, cfg ZcodeCaptchaConfig, solve zcodeCaptchaSolver) {
	ticker := time.NewTicker(zcodeCaptchaRefillInterval)
	defer ticker.Stop()
	p.checkAndSolve(ctx, cfg, solve)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		p.checkAndSolve(ctx, cfg, solve)
	}
}

func (p *zcodeCaptchaPool) checkAndSolve(ctx context.Context, cfg ZcodeCaptchaConfig, solve zcodeCaptchaSolver) {
	p.mu.Lock()
	p.dropExpiredLocked()
	need := p.kick || len(p.tokens) < zcodeCaptchaPoolMin
	if !need || p.solving >= zcodeCaptchaMaxSolving {
		p.mu.Unlock()
		return
	}
	p.kick = false
	p.solving++
	p.mu.Unlock()

	go func() {
		defer func() {
			p.mu.Lock()
			p.solving--
			p.mu.Unlock()
		}()
		solveCtx, cancel := context.WithTimeout(ctx, zcodeCaptchaSolveWait)
		defer cancel()
		param, err := solve.Solve(solveCtx, cfg)
		p.mu.Lock()
		if err != nil {
			p.lastErr = err.Error()
			p.lastErrAt = time.Now()
		} else {
			p.lastErr = ""
			p.lastErrAt = time.Time{}
			p.tokens = append(p.tokens, zcodeCaptchaToken{
				VerifyParam: param,
				Region:      cfg.Region,
				expiresAt:   time.Now().Add(zcodeCaptchaTokenTTL),
			})
			p.trimLocked()
		}
		p.broadcastLocked()
		p.mu.Unlock()
	}()
}

func (p *zcodeCaptchaPool) trimLocked() {
	p.dropExpiredLocked()
	for len(p.tokens) > zcodeCaptchaPoolMax {
		p.tokens = p.tokens[1:]
	}
}

func (p *zcodeCaptchaPool) size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dropExpiredLocked()
	return len(p.tokens)
}

// ── 管理器（进程级单例，懒启动） ─────────────────────────────────────────────

type zcodeCaptchaState int

const (
	zcodeCaptchaIdle zcodeCaptchaState = iota
	zcodeCaptchaDisabled
	zcodeCaptchaRunning
	zcodeCaptchaUnavailable
)

// zcodeCaptchaSolver 抽象无痕验证求解（rod 实现 + 测试 fake）。
type zcodeCaptchaSolver interface {
	Solve(ctx context.Context, cfg ZcodeCaptchaConfig) (string, error)
}

type zcodeCaptchaManager struct {
	mu           sync.Mutex
	state        zcodeCaptchaState
	reason       string
	cfg          *ZcodeCaptchaConfig
	cfgFetchedAt time.Time
	pool         *zcodeCaptchaPool
	solver       zcodeCaptchaSolver
	// 测试注入：nil 时用真实 rod 求解器。
	solverFactory func() (zcodeCaptchaSolver, error)
}

// zcodeCaptcha 是进程级单例：仅在首个 zcode 试用套餐请求时懒启动，
// Coding Plan 路径零开销。
var zcodeCaptcha = &zcodeCaptchaManager{}

// zcodeCaptchaTokenFor 返回一个验证码 token；上游未启用验证码时返回 (nil, nil)，
// 调用方跳过附加头即可。求解器不可用/解失败时返回错误（调用方请求继续发出，
// 由 3007 兜底提示解释）。
func zcodeCaptchaTokenFor(ctx context.Context) (*zcodeCaptchaToken, error) {
	return zcodeCaptcha.token(ctx)
}

// zcodeFetchCaptchaConfigFn 可在测试中替换（避免单测访问真实上游）。
var zcodeFetchCaptchaConfigFn = fetchZcodeCaptchaConfig

func (m *zcodeCaptchaManager) token(ctx context.Context) (*zcodeCaptchaToken, error) {
	m.mu.Lock()
	switch m.state {
	case zcodeCaptchaDisabled:
		m.mu.Unlock()
		return nil, nil
	case zcodeCaptchaUnavailable:
		err := fmt.Errorf("zcode captcha solver unavailable: %s", m.reason)
		m.mu.Unlock()
		return nil, err
	case zcodeCaptchaRunning:
		pool := m.pool
		m.mu.Unlock()
		m.refreshConfigAsync()
		return pool.take(ctx)
	}
	// idle：拉配置并启动。
	cfg, err := zcodeFetchCaptchaConfigFn(ctx)
	if err != nil {
		m.state = zcodeCaptchaUnavailable
		m.reason = fmt.Sprintf("config fetch failed: %v", err)
		m.mu.Unlock()
		return nil, fmt.Errorf("zcode captcha: %s", m.reason)
	}
	m.cfg, m.cfgFetchedAt = cfg, time.Now()
	if !cfg.Enabled || cfg.Prefix == "" || cfg.SceneID == "" {
		m.state = zcodeCaptchaDisabled
		m.mu.Unlock()
		return nil, nil
	}
	factory := m.solverFactory
	if factory == nil {
		factory = newZcodeCaptchaBrowserSolver
	}
	solver, err := factory()
	if err != nil {
		m.state = zcodeCaptchaUnavailable
		m.reason = err.Error()
		m.mu.Unlock()
		return nil, fmt.Errorf("zcode captcha solver: %s", m.reason)
	}
	m.solver = solver
	m.pool = newZcodeCaptchaPool()
	m.state = zcodeCaptchaRunning
	pool, solverRun := m.pool, solver
	m.mu.Unlock()

	go pool.refillLoop(context.Background(), *cfg, solverRun)
	return pool.take(ctx)
}

// refreshConfigAsync 周期性重拉场景配置（enabled 翻转时热切换）。
func (m *zcodeCaptchaManager) refreshConfigAsync() {
	m.mu.Lock()
	if m.state != zcodeCaptchaRunning || time.Since(m.cfgFetchedAt) < zcodeCaptchaConfigTTL {
		m.mu.Unlock()
		return
	}
	m.cfgFetchedAt = time.Now() // 防重复调度
	m.mu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cfg, err := zcodeFetchCaptchaConfigFn(ctx)
		if err != nil {
			return
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		m.cfg, m.cfgFetchedAt = cfg, time.Now()
		if !cfg.Enabled && m.state == zcodeCaptchaRunning {
			m.state = zcodeCaptchaDisabled
		}
	}()
}

// Stats 暴露池状态（诊断用）。
func (m *zcodeCaptchaManager) stats() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]any{"state": zcodeCaptchaStateString(m.state)}
	if m.reason != "" {
		out["reason"] = m.reason
	}
	if m.cfg != nil {
		out["enabled"] = m.cfg.Enabled
		out["region"] = m.cfg.Region
	}
	if m.pool != nil {
		out["pool"] = m.pool.size()
	}
	return out
}

func zcodeCaptchaStateString(s zcodeCaptchaState) string {
	switch s {
	case zcodeCaptchaDisabled:
		return "disabled"
	case zcodeCaptchaRunning:
		return "running"
	case zcodeCaptchaUnavailable:
		return "unavailable"
	default:
		return "idle"
	}
}

// zcodeCaptchaChromeBin 返回优先级最高的本机 Chrome 可执行文件路径。
func zcodeCaptchaChromeBin() string {
	if bin := strings.TrimSpace(os.Getenv("ZCODE_CAPTCHA_CHROME_BIN")); bin != "" {
		return bin
	}
	for _, name := range []string{
		"chromium-browser", "chromium", "google-chrome", "google-chrome-stable",
		"chrome", "chrome-headless-shell", "headless_shell",
	} {
		if path, err := exec.LookPath(name); err == nil && path != "" {
			return path
		}
	}
	return ""
}
