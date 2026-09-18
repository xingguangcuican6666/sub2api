/**
 * Admin ZCode (Z.AI / bigmodel GLM Coding Plan) API endpoints.
 * OAuth login flow + coding plan quota probe.
 */

import { apiClient } from '../client'

/** 开始登录的返回（对齐后端 service.ZcodeAuthURLResult）。 */
export interface ZcodeAuthURLResult {
  /** "poll"（zai 服务端中转）或 "paste"（bigmodel 粘贴回调）。 */
  mode: 'poll' | 'paste'
  provider: 'zai' | 'bigmodel'
  auth_url: string
  session_id: string
  redirect_uri?: string
  expires_at?: number
}

/** 登录状态（对齐后端 service.ZcodeLoginStatus）。 */
export interface ZcodeLoginStatus {
  status: 'pending' | 'ready' | 'failed'
  message?: string
  /** ready 时返回可直接作为账号凭据的对象。 */
  credentials?: Record<string, unknown>
}

export const zcodeApi = {
  /** 发起 OAuth 登录，返回授权 URL。 */
  async startLogin(
    provider: 'zai' | 'bigmodel',
    proxyId: number | null
  ): Promise<ZcodeAuthURLResult> {
    // 拦截器已把 { code, message, data } 壳解成 data，这里必须再取一层
    // response.data 才能拿到真正的业务字段（与 grok / cnProviders 同约定）。
    const { data } = await apiClient.post<ZcodeAuthURLResult>('/admin/zcode/oauth/url', {
      provider,
      proxy_id: proxyId ?? null
    })
    return data
  },

  /** 轮询 zai CLI 登录状态（前端以数秒间隔调用直到 ready / failed）。 */
  async pollLogin(sessionId: string): Promise<ZcodeLoginStatus> {
    const { data } = await apiClient.post<ZcodeLoginStatus>('/admin/zcode/oauth/poll', {
      session_id: sessionId
    })
    return data
  },

  /** bigmodel：用粘贴的回调 URL 完成 auth-code 换取。 */
  async completeCallback(sessionId: string, callbackUrl: string): Promise<ZcodeLoginStatus> {
    const { data } = await apiClient.post<ZcodeLoginStatus>('/admin/zcode/oauth/callback', {
      session_id: sessionId,
      callback_url: callbackUrl
    })
    return data
  }
}