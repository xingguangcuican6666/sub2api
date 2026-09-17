package admin

import (
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/gin-gonic/gin"
)

// ZcodeOAuthHandler 处理 ZCode 平台（Z.AI / 智谱 GLM Coding Plan）的 OAuth 登录。
//
// 两种流程（对齐 zcode-api auth 流程）：
//   - zai：服务端中转 CLI 登录。前端拿 authorize_url 引导用户授权，
//     然后轮询 poll 端点直到 ready（凭据解析在 ready 时同步完成）。
//   - bigmodel：粘贴回调。前端展示 authorize_url，用户授权后浏览器跳转
//     127.0.0.1 回调（连接失败但地址栏含 authCode），把最终 URL 粘贴回
//     callback 端点完成换取。
type ZcodeOAuthHandler struct {
	zcodeOAuthService *service.ZcodeOAuthService
}

func NewZcodeOAuthHandler(zcodeOAuthService *service.ZcodeOAuthService) *ZcodeOAuthHandler {
	return &ZcodeOAuthHandler{zcodeOAuthService: zcodeOAuthService}
}

type ZcodeStartLoginRequest struct {
	// Provider 为上游供应商："zai"（Z.AI）或 "bigmodel"（智谱开放平台）。
	Provider string `json:"provider" binding:"required"`
	// ProxyID 可选：登录流量（init/poll/token 换取 + Key 解析）走指定代理。
	ProxyID *int64 `json:"proxy_id"`
}

// StartLogin 发起 ZCode OAuth 登录。
// POST /api/v1/admin/zcode/oauth/url
func (h *ZcodeOAuthHandler) StartLogin(c *gin.Context) {
	var req ZcodeStartLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}
	provider := strings.TrimSpace(req.Provider)
	if provider != service.ZcodeProviderZai && provider != service.ZcodeProviderBigmodel {
		response.BadRequest(c, "Invalid provider: must be 'zai' or 'bigmodel'")
		return
	}
	result, err := h.zcodeOAuthService.StartLogin(c.Request.Context(), provider, req.ProxyID)
	if err != nil {
		response.InternalError(c, "Failed to start zcode login: "+err.Error())
		return
	}
	response.Success(c, result)
}

type ZcodeSessionRequest struct {
	SessionID string `json:"session_id" binding:"required"`
}

// PollLogin 轮询 zai CLI 登录状态（pending / ready / failed）。
// POST /api/v1/admin/zcode/oauth/poll
func (h *ZcodeOAuthHandler) PollLogin(c *gin.Context) {
	var req ZcodeSessionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}
	status, err := h.zcodeOAuthService.PollLogin(c.Request.Context(), req.SessionID)
	if err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	response.Success(c, status)
}

type ZcodeCallbackRequest struct {
	SessionID string `json:"session_id" binding:"required"`
	// CallbackURL 为用户从浏览器地址栏粘贴的完整回调 URL（含 authCode 与 state）。
	CallbackURL string `json:"callback_url" binding:"required"`
}

// CompleteCallback 用粘贴的回调 URL 完成 bigmodel auth-code 登录。
// POST /api/v1/admin/zcode/oauth/callback
func (h *ZcodeOAuthHandler) CompleteCallback(c *gin.Context) {
	var req ZcodeCallbackRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}
	status, err := h.zcodeOAuthService.CompleteBigmodelLogin(c.Request.Context(), req.SessionID, req.CallbackURL)
	if err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	response.Success(c, status)
}
