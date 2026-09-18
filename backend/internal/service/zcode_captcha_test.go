//go:build unit

package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ── helpers ──────────────────────────────────────────────────────────────────

type fakeZcodeCaptchaSolver struct {
	mu     sync.Mutex
	params []string
	err    error
	calls  int
}

func (f *fakeZcodeCaptchaSolver) Solve(ctx context.Context, cfg ZcodeCaptchaConfig) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return "", f.err
	}
	if len(f.params) == 0 {
		return "", nil
	}
	p := f.params[0]
	f.params = f.params[1:]
	return p, nil
}

func zcodeCaptchaTestParam(secToken string) string {
	payload, _ := json.Marshal(map[string]any{
		"certifyId":     "cap-cert-1",
		"sceneId":       "11xygtvd",
		"isSign":        true,
		"securityToken": secToken,
	})
	return base64.StdEncoding.EncodeToString(payload)
}

func zcodeCaptchaValidToken() string { return zcodeCaptchaTestParam(strings.Repeat("s", 120)) }

// zcodeCaptchaSetManagerForTest 替换验证码管理器单例（测试结束自动恢复）。
func zcodeCaptchaSetManagerForTest(t *testing.T, mutate func(m *zcodeCaptchaManager)) {
	t.Helper()
	old := zcodeCaptcha
	t.Cleanup(func() { zcodeCaptcha = old })
	m := &zcodeCaptchaManager{}
	if mutate != nil {
		mutate(m)
	}
	zcodeCaptcha = m
}

func zcodeCaptchaRunningManager(t *testing.T, solver zcodeCaptchaSolver, tokens ...zcodeCaptchaToken) *zcodeCaptchaManager {
	t.Helper()
	zcodeCaptchaRefillInterval = 10 * time.Millisecond
	t.Cleanup(func() { zcodeCaptchaRefillInterval = 3 * time.Second })
	pool := newZcodeCaptchaPool()
	for _, tok := range tokens {
		pool.tokens = append(pool.tokens, tok)
	}
	m := &zcodeCaptchaManager{
		state:  zcodeCaptchaRunning,
		cfg:    &ZcodeCaptchaConfig{Enabled: true, Prefix: "no8xfe", SceneID: "11xygtvd", Region: "cn"},
		pool:   pool,
		solver: solver,
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go pool.refillLoop(ctx, *m.cfg, solver)
	return m
}

// ── verifyParam 校验 ─────────────────────────────────────────────────────────

func TestZcodeValidateVerifyParam(t *testing.T) {
	ok, err := zcodeValidateVerifyParam(zcodeCaptchaValidToken())
	require.NoError(t, err)
	require.Equal(t, zcodeCaptchaValidToken(), ok)

	_, err = zcodeValidateVerifyParam("short")
	require.ErrorContains(t, err, "too short")

	// 缺 securityToken 的降级产物必须拒收（发出必 3007）。
	// 长度足够但缺 securityToken 的降级产物必须拒收（发出必 3007）。
	degraded, _ := json.Marshal(map[string]any{"certifyId": strings.Repeat("x", 160), "isSign": true})
	_, err = zcodeValidateVerifyParam(base64.StdEncoding.EncodeToString(degraded))
	require.ErrorContains(t, err, "securityToken")

	_, err = zcodeValidateVerifyParam(strings.Repeat("%", 300))
	require.ErrorContains(t, err, "base64")
}

// ── 挑战检测 ─────────────────────────────────────────────────────────────────

func TestZcodeCaptchaChallengeDetection(t *testing.T) {
	header := http.Header{}
	require.False(t, zcodeCaptchaChallenge(header, []byte(`{"code":0,"msg":""}`)))

	header.Set(ZcodeCaptchaParamHeader, "challenge-param")
	require.True(t, zcodeCaptchaChallenge(header, nil))

	empty := http.Header{}
	require.True(t, zcodeCaptchaChallenge(empty, []byte(`{"code":3007,"msg":"captcha verify failed"}`)))
	require.True(t, zcodeCaptchaChallenge(empty, []byte(`{"code": 3007}`)))
	require.False(t, zcodeCaptchaChallenge(empty, []byte(`{"code":0}`)))
	require.False(t, zcodeCaptchaChallenge(empty, nil))
}

// ── token 池 ─────────────────────────────────────────────────────────────────

func TestZcodeCaptchaPoolTakePrefilled(t *testing.T) {
	pool := newZcodeCaptchaPool()
	tok := zcodeCaptchaToken{VerifyParam: "p1", Region: "cn", expiresAt: time.Now().Add(time.Minute)}
	pool.tokens = append(pool.tokens, tok)

	got, err := pool.take(context.Background())
	require.NoError(t, err)
	require.Equal(t, "p1", got.VerifyParam)
	require.Zero(t, pool.size())
}

func TestZcodeCaptchaPoolDropsExpired(t *testing.T) {
	pool := newZcodeCaptchaPool()
	pool.tokens = append(pool.tokens, zcodeCaptchaToken{
		VerifyParam: "stale", Region: "cn", expiresAt: time.Now().Add(-time.Second),
	})
	require.Zero(t, pool.size())
}

func TestZcodeCaptchaPoolFastFailsAfterSolverError(t *testing.T) {
	pool := newZcodeCaptchaPool()
	pool.lastErr = "boom"
	pool.lastErrAt = time.Now()

	_, err := pool.take(context.Background())
	require.ErrorContains(t, err, "boom")
}

func TestZcodeCaptchaPoolRefillLoopSolvesOnDemand(t *testing.T) {
	zcodeCaptchaRefillInterval = 5 * time.Millisecond
	t.Cleanup(func() { zcodeCaptchaRefillInterval = 3 * time.Second })

	solver := &fakeZcodeCaptchaSolver{params: []string{zcodeCaptchaValidToken(), zcodeCaptchaValidToken()}}
	pool := newZcodeCaptchaPool()
	cfg := ZcodeCaptchaConfig{Enabled: true, Prefix: "no8xfe", SceneID: "11xygtvd", Region: "cn"}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pool.refillLoop(ctx, cfg, solver)

	got, err := pool.take(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, got.VerifyParam)
	require.Equal(t, "cn", got.Region)
}

// ── 管理器 ───────────────────────────────────────────────────────────────────

func TestZcodeCaptchaManagerDisabled(t *testing.T) {
	zcodeCaptchaSetManagerForTest(t, func(m *zcodeCaptchaManager) { m.state = zcodeCaptchaDisabled })

	tok, err := zcodeCaptchaTokenFor(context.Background())
	require.NoError(t, err)
	require.Nil(t, tok, "上游未启用验证码时应跳过附加头")
}

func TestZcodeCaptchaManagerUnavailable(t *testing.T) {
	zcodeCaptchaSetManagerForTest(t, func(m *zcodeCaptchaManager) {
		m.state = zcodeCaptchaUnavailable
		m.reason = "no chrome"
	})

	_, err := zcodeCaptchaTokenFor(context.Background())
	require.ErrorContains(t, err, "no chrome")
}

func TestZcodeCaptchaManagerRunningServesToken(t *testing.T) {
	zcodeCaptchaSetManagerForTest(t, func(m *zcodeCaptchaManager) {
		*m = *zcodeCaptchaRunningManager(t, &fakeZcodeCaptchaSolver{}, zcodeCaptchaToken{
			VerifyParam: zcodeCaptchaValidToken(), Region: "cn", expiresAt: time.Now().Add(time.Minute),
		})
	})

	tok, err := zcodeCaptchaTokenFor(context.Background())
	require.NoError(t, err)
	require.NotNil(t, tok)
	require.Equal(t, "cn", tok.Region)
}

func TestZcodeCaptchaManagerColdStartUsesFactory(t *testing.T) {
	zcodeCaptchaSetManagerForTest(t, func(m *zcodeCaptchaManager) {
		m.solverFactory = func() (zcodeCaptchaSolver, error) {
			return &fakeZcodeCaptchaSolver{params: []string{zcodeCaptchaValidToken()}}, nil
		}
	})
	oldFetch := zcodeFetchCaptchaConfigFn
	zcodeFetchCaptchaConfigFn = func(ctx context.Context) (*ZcodeCaptchaConfig, error) {
		return &ZcodeCaptchaConfig{Enabled: true, Prefix: "no8xfe", SceneID: "11xygtvd", Region: "cn"}, nil
	}
	t.Cleanup(func() { zcodeFetchCaptchaConfigFn = oldFetch })

	tok, err := zcodeCaptchaTokenFor(context.Background())
	require.NoError(t, err)
	require.NotNil(t, tok)
	require.Equal(t, zcodeCaptchaRunning, zcodeCaptcha.state)
}

func TestZcodeCaptchaManagerColdStartDisabledUpstream(t *testing.T) {
	zcodeCaptchaSetManagerForTest(t, nil)
	oldFetch := zcodeFetchCaptchaConfigFn
	zcodeFetchCaptchaConfigFn = func(ctx context.Context) (*ZcodeCaptchaConfig, error) {
		return &ZcodeCaptchaConfig{Enabled: false}, nil
	}
	t.Cleanup(func() { zcodeFetchCaptchaConfigFn = oldFetch })

	tok, err := zcodeCaptchaTokenFor(context.Background())
	require.NoError(t, err)
	require.Nil(t, tok)
	require.Equal(t, zcodeCaptchaDisabled, zcodeCaptcha.state)
}

func TestZcodeCaptchaManagerConfigFetchFailure(t *testing.T) {
	zcodeCaptchaSetManagerForTest(t, nil)
	oldFetch := zcodeFetchCaptchaConfigFn
	zcodeFetchCaptchaConfigFn = func(ctx context.Context) (*ZcodeCaptchaConfig, error) {
		return nil, context.DeadlineExceeded
	}
	t.Cleanup(func() { zcodeFetchCaptchaConfigFn = oldFetch })

	_, err := zcodeCaptchaTokenFor(context.Background())
	require.Error(t, err)
	require.Equal(t, zcodeCaptchaUnavailable, zcodeCaptcha.state)
}

// TestZcodeCaptchaLiveSolve 用真实 Chromium + 线上场景配置跑一次无痕验证。
// 仅在本机验证时运行：
//
//	ZCODE_CAPTCHA_LIVE_TEST=1 ZCODE_CAPTCHA_PROXY=http://127.0.0.1:7890 \
//	go test -tags unit -run TestZcodeCaptchaLiveSolve
func TestZcodeCaptchaLiveSolve(t *testing.T) {
	if os.Getenv("ZCODE_CAPTCHA_LIVE_TEST") != "1" {
		t.Skip("set ZCODE_CAPTCHA_LIVE_TEST=1 to run the live aliyun captcha solve")
	}
	cfg, err := fetchZcodeCaptchaConfig(context.Background())
	if err != nil {
		// 配置拉取不走代理（httpclient 直连）；沙箱内用 2026-09-18 实测的线上
		// 场景配置兜底，聚焦验证求解器本身。
		t.Logf("config fetch failed (%v), using known-live scene config", err)
		cfg = &ZcodeCaptchaConfig{Enabled: true, Prefix: "no8xfe", SceneID: "11xygtvd", Region: "cn"}
	}
	require.True(t, cfg.Enabled, "captcha should be enabled upstream")

	solver, err := newZcodeCaptchaBrowserSolver()
	require.NoError(t, err)
	defer func() { _ = solver.(*zcodeRodSolver).browser.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	param, err := solver.Solve(ctx, *cfg)
	require.NoError(t, err)
	require.Greater(t, len(param), 200)
	t.Logf("live solve ok: verifyParam %d chars (prefix %.40s...)", len(param), param)
}
