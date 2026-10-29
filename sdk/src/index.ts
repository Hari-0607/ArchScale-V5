import axios, { AxiosInstance, AxiosRequestConfig } from 'axios';

export type ApiResult<T> =
  | { ok: true; data: T }
  | { ok: false; status: number; code: string; message: string };

export interface XAuthClientOptions {
  baseURL?: string;
  onUnauthorized?: () => void;
}

/** Small bearer/context SDK for independently deployed apps consuming XAuth. */
export class XAuthClient {
  private readonly http: AxiosInstance;
  private token: string | null = null;
  private refreshToken: string | null = null;
  private contextId: string | null = null;

  constructor(options: XAuthClientOptions = {}) {
    this.http = axios.create({ baseURL: options.baseURL || '', timeout: 15000 });
    this.onUnauthorized = options.onUnauthorized;
  }

  private readonly onUnauthorized?: () => void;

  setAccessToken(token: string | null): void { this.token = token; }
  setRefreshToken(token: string | null): void { this.refreshToken = token; }
  setContext(contextId: string | null): void { this.contextId = contextId; }
  clear(): void { this.token = null; this.refreshToken = null; this.contextId = null; }

  async request<T>(url: string, method = 'GET', body?: unknown, accessToken?: string): Promise<ApiResult<T>> {
    const headers: Record<string, string> = {};
    const token = accessToken ?? this.token;
    if (token) headers.Authorization = `Bearer ${token}`;
    if (this.contextId) headers['X-ArchScale-Context'] = this.contextId;
    const config: AxiosRequestConfig = { url, method, headers, data: body };
    try {
      const response = await this.http.request<T>(config);
      return { ok: true, data: response.data };
    } catch (error: any) {
      const status: number = error?.response?.status ?? 0;
      const bodyData = error?.response?.data;
      if (status === 401 && this.refreshToken && url !== '/api/session/refresh') {
        try {
          const refreshed = await this.http.post('/api/session/refresh', { refreshToken:this.refreshToken });
          this.setAccessToken(refreshed.data.accessToken);
          this.setRefreshToken(refreshed.data.refreshToken);
          const retryHeaders = { ...headers, Authorization:`Bearer ${this.token}` };
          const retry = await this.http.request<T>({ ...config, headers:retryHeaders });
          return { ok:true,data:retry.data };
        } catch { this.onUnauthorized?.(); }
      }
      if (status === 401) this.onUnauthorized?.();
      if (status === 401) return { ok:false,status,code:'UNAUTHENTICATED',message:'Your session has expired. Please sign in again.' };
      if (status === 403) return { ok:false,status,code:bodyData?.code ?? bodyData?.error ?? 'FORBIDDEN',message:bodyData?.message ?? 'You do not have permission to do that.' };
      if (status === 429) return { ok:false,status,code:'RATE_LIMITED',message:'Too many attempts. Please wait and try again.' };
      return { ok:false,status,code:bodyData?.code ?? bodyData?.error ?? (status ? String(status) : 'NETWORK_ERROR'),message:bodyData?.message ?? bodyData?.error ?? (status ? `Request failed (${status})` : 'Network error. Check your connection and try again.') };
    }
  }
}
