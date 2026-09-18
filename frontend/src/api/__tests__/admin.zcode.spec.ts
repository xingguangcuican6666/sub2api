import { beforeEach, describe, expect, it, vi } from 'vitest'

const { post } = vi.hoisted(() => ({
  post: vi.fn(),
}))

vi.mock('@/api/client', () => ({
  apiClient: { post },
}))

import { zcodeApi } from '@/api/admin/zcode'

/**
 * zcode OAuth 方法必须解包 axios response 的 .data 后再返回。
 *
 * 共享拦截器把后端的 { code, message, data } 壳替换成 response.data，但
 * apiClient.post() 返回的仍是 AxiosResponse —— 直接把该对象透传出去，调用方
 * 读 session_id / mode / auth_url 全是 undefined，授权弹窗打不开、粘贴回调
 * 框也不出现。
 */
describe('admin ZCode OAuth API', () => {
  beforeEach(() => {
    post.mockReset()
  })

  it('startLogin 返回解包后的业务对象而非 AxiosResponse', async () => {
    const payload = {
      mode: 'paste',
      provider: 'bigmodel',
      auth_url: 'https://bigmodel.cn/login?appId=zcode',
      session_id: 'session-1',
      redirect_uri: 'http://127.0.0.1:62156/oauth/callback/bigmodel',
    }
    post.mockResolvedValueOnce({ data: payload, status: 200 })

    const result = await zcodeApi.startLogin('bigmodel', null)

    expect(post).toHaveBeenCalledWith('/admin/zcode/oauth/url', {
      provider: 'bigmodel',
      proxy_id: null,
    })
    expect(result).toEqual(payload)
    expect(result.session_id).toBe('session-1')
    expect(result.mode).toBe('paste')
    expect(result.auth_url).toBe(payload.auth_url)
  })

  it('pollLogin 返回解包后的登录状态', async () => {
    post.mockResolvedValueOnce({
      data: { status: 'ready', credentials: { api_key: 'key' } },
      status: 200,
    })

    const status = await zcodeApi.pollLogin('session-1')

    expect(post).toHaveBeenCalledWith('/admin/zcode/oauth/poll', { session_id: 'session-1' })
    expect(status.status).toBe('ready')
    expect(status.credentials).toEqual({ api_key: 'key' })
  })

  it('completeCallback 返回解包后的登录状态', async () => {
    post.mockResolvedValueOnce({ data: { status: 'failed', message: 'bad code' }, status: 200 })

    const status = await zcodeApi.completeCallback('session-1', 'http://127.0.0.1/cb?code=x')

    expect(post).toHaveBeenCalledWith('/admin/zcode/oauth/callback', {
      session_id: 'session-1',
      callback_url: 'http://127.0.0.1/cb?code=x',
    })
    expect(status.status).toBe('failed')
    expect(status.message).toBe('bad code')
  })

  it('保留 proxy_id 显式传值', async () => {
    post.mockResolvedValueOnce({
      data: { mode: 'poll', provider: 'zai', auth_url: 'https://chat.z.ai/x', session_id: 's' },
      status: 200,
    })

    await zcodeApi.startLogin('zai', 7)

    expect(post).toHaveBeenCalledWith('/admin/zcode/oauth/url', {
      provider: 'zai',
      proxy_id: 7,
    })
  })
})