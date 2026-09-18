package service

// rod（headless Chrome）实现的阿里云验证码无痕求解器。
//
// 对齐 TriDefender/zcode-api captcha-happy.ts 的求解契约，但用真实浏览器
// 替代 happy-dom 自制 DOM 仿真——指纹天然真实，无需 native-masking 等补丁：
//   1. 打开 https://zcode.z.ai/ 完成 cookie/origin 预热（求解页与场景域一致，
//      风控按 Origin/Referer 打分）；
//   2. 注入引导页（AliyunCaptcha.js + #cap/#btn 挂载点），bypass CSP 后
//      CDN 脚本可加载；
//   3. initAliyunCaptcha({mode:"popup", ...}) + startTracelessVerification()
//      产出 verifyParam（一次性、~95s 过期）；
//   4. 严格校验产物（≥200 字符且含 securityToken），降级产物直接弃用。

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

const (
	zcodeCaptchaPrimeURL  = "https://zcode.z.ai/"
	zcodeCaptchaSDKScript = "https://o.alicdn.com/captcha-frontend/aliyunCaptcha/AliyunCaptcha.js"
	zcodeCaptchaBootstrap = `<!DOCTYPE html><html><head></head><body>
<div id="cap"></div><button id="btn"></button>
<script src="` + zcodeCaptchaSDKScript + `"></script>
</body></html>`
)

type zcodeRodSolver struct {
	mu      sync.Mutex
	browser *rod.Browser
	sem     chan struct{}
}

// newZcodeCaptchaBrowserSolver 启动常驻 headless Chrome（进程生命周期内复用）。
// ZCODE_CAPTCHA_PROXY 可让浏览器走代理（部署环境无法直连 z.ai / 阿里云时）。
func newZcodeCaptchaBrowserSolver() (zcodeCaptchaSolver, error) {
	l := launcher.New().
		Headless(true).
		NoSandbox(true).
		Set("disable-dev-shm-usage").
		Set("disable-gpu").
		// leakless 助手在 musl（Alpine）下不可用，且子进程经 DevTools 管道
		// 随父进程退出，无需强杀。
		Leakless(false)

	if proxy := strings.TrimSpace(os.Getenv("ZCODE_CAPTCHA_PROXY")); proxy != "" {
		l = l.Set("proxy-server", proxy)
	}

	bin := zcodeCaptchaChromeBin()
	if bin != "" {
		l = l.Bin(bin)
	} else if os.Getenv("ZCODE_CAPTCHA_AUTO_DOWNLOAD") != "0" {
		managed, err := launcher.NewBrowser().Get()
		if err != nil {
			return nil, fmt.Errorf("no system Chrome and managed browser download failed: %w", err)
		}
		l = l.Bin(managed)
	} else {
		return nil, fmt.Errorf("no Chrome found (set ZCODE_CAPTCHA_CHROME_BIN or install chromium)")
	}

	controlURL, err := l.Launch()
	if err != nil {
		return nil, fmt.Errorf("launch chrome: %w", err)
	}
	browser := rod.New().ControlURL(controlURL)
	if err := browser.Connect(); err != nil {
		return nil, fmt.Errorf("connect chrome: %w", err)
	}
	return &zcodeRodSolver{browser: browser, sem: make(chan struct{}, zcodeCaptchaMaxSolving)}, nil
}

// Solve 执行一次无痕验证，返回经校验的 verifyParam。
func (s *zcodeRodSolver) Solve(ctx context.Context, cfg ZcodeCaptchaConfig) (string, error) {
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-ctx.Done():
		return "", ctx.Err()
	}

	s.mu.Lock()
	browser := s.browser
	s.mu.Unlock()

	solveCtx, cancel := context.WithTimeout(ctx, zcodeCaptchaSolveWait)
	defer cancel()

	incognito, err := browser.Incognito()
	if err != nil {
		return "", fmt.Errorf("captcha incognito: %w", err)
	}
	defer func() { _ = incognito.Close() }()

	page, err := incognito.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		return "", fmt.Errorf("captcha page: %w", err)
	}
	page = page.Context(solveCtx)
	defer func() { _ = page.Close() }()

	// 在真实场景域上预热 cookie/origin，再注入引导页（origin 保持 zcode.z.ai）。
	if err := page.Navigate(zcodeCaptchaPrimeURL); err != nil {
		return "", fmt.Errorf("captcha prime navigate: %w", err)
	}
	_ = page.WaitLoad()
	_ = page.WaitStable(300 * time.Millisecond)
	if err := (proto.PageSetBypassCSP{Enabled: true}).Call(page); err != nil {
		return "", fmt.Errorf("captcha bypass csp: %w", err)
	}
	if err := page.SetDocumentContent(zcodeCaptchaBootstrap); err != nil {
		return "", fmt.Errorf("captcha bootstrap: %w", err)
	}

	// 等待阿里云 SDK 就绪（rod 的 Eval 要求函数表达式）。
	deadline := time.Now().Add(15 * time.Second)
	for {
		ready, err := page.Eval(`() => typeof window.initAliyunCaptcha === 'function'`)
		if err == nil && ready != nil && ready.Value.Bool() {
			break
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("aliyun captcha sdk not ready in time: %s", zcodeCaptchaPageDiagnostics(page))
		}
		select {
		case <-solveCtx.Done():
			return "", solveCtx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}

	param, err := s.runTracelessVerification(page, solveCtx, cfg)
	if err != nil {
		return "", err
	}
	return zcodeValidateVerifyParam(param)
}

// runTracelessVerification 调用 SDK 的无痕验证并在 success 回调中取 verifyParam。
func (s *zcodeRodSolver) runTracelessVerification(page *rod.Page, ctx context.Context, cfg ZcodeCaptchaConfig) (string, error) {
	script := fmt.Sprintf(`() => new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error('captcha solve timeout')), %d);
  const finish = (fn) => (value) => { clearTimeout(timer); fn(value); };
  try {
    window.initAliyunCaptcha({
      SceneId: %q,
      mode: 'popup',
      region: %q,
      prefix: %q,
      language: 'en',
      element: '#cap',
      button: '#btn',
      captchaLogoImg: '',
      showErrorTip: false,
      getInstance: (inst) => {
        try {
          (inst.startTracelessVerification || inst.show).call(inst);
        } catch (e) {
          clearTimeout(timer);
          reject(new Error('start: ' + (e && e.message ? e.message : String(e))));
        }
      },
      success: (result) => {
        clearTimeout(timer);
        try {
          if (result && typeof result === 'object' && result.verifyResult === false) {
            reject(new Error('verify rejected: ' + JSON.stringify({verifyCode: result.verifyCode, certifyId: result.certifyId})));
            return;
          }
          resolve(result);
        } catch (e) { reject(e); }
      },
      fail: (err) => { clearTimeout(timer); reject(new Error('fail: ' + JSON.stringify(err))); },
      onError: (err) => { clearTimeout(timer); reject(new Error('onError: ' + JSON.stringify(err))); },
    });
  } catch (e) {
    clearTimeout(timer);
    reject(e);
  }
})`,
		zcodeCaptchaSolveWait.Milliseconds(), cfg.SceneID, cfg.Region, cfg.Prefix)

	res, err := page.Context(ctx).Eval(script)
	if err != nil {
		return "", fmt.Errorf("captcha solve: %w", err)
	}
	return zcodeExtractVerifyParamFromResult(res)
}

// zcodeCaptchaPageDiagnostics 采集 SDK 未就绪时的页面状态（运维排障用）。
func zcodeCaptchaPageDiagnostics(page *rod.Page) string {
	res, err := page.Eval(`() => JSON.stringify({
  href: location.href,
  readyState: document.readyState,
  hasSDK: typeof window.initAliyunCaptcha,
  scripts: Array.from(document.scripts).map(s => ({src: String(s.src).slice(0, 90), async: s.async}))
})`)
	if err != nil {
		return "diagnostics unavailable: " + err.Error()
	}
	return res.Value.Str()
}

// zcodeExtractVerifyParamFromResult 从 success 回调结果中提取 verifyParam
// （兼容 verifyParam / data / param 字段与字符串直返；对齐 extractVerifyParam）。
func zcodeExtractVerifyParamFromResult(res *proto.RuntimeRemoteObject) (string, error) {
	if res == nil {
		return "", fmt.Errorf("captcha result missing")
	}
	value := res.Value
	if str, ok := value.Val().(string); ok {
		return str, nil
	}
	for _, key := range []string{"verifyParam", "data", "param"} {
		field := value.Get(key)
		if field.Nil() {
			continue
		}
		if str, ok := field.Val().(string); ok && strings.TrimSpace(str) != "" {
			return str, nil
		}
	}
	raw, _ := json.Marshal(value.Val())
	return "", fmt.Errorf("captcha result has no verifyParam: %.120s", string(raw))
}
