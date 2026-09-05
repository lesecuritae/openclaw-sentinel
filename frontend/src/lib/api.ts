export class ApiClient {
  constructor(private readonly token: string, private readonly base = "/api/v1") {}

  private async request<T>(path: string, init?: RequestInit): Promise<T> {
    const response = await fetch(`${this.base}${path}`, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.token}`,
        ...init?.headers,
      },
    });
    if (!response.ok) throw new Error(`Request failed (${response.status})`);
    return response.json() as Promise<T>;
  }

  get<T>(path: string): Promise<T> { return this.request<T>(path); }
  post<T>(path: string, value: unknown): Promise<T> {
    return this.request<T>(path, { method: "POST", body: JSON.stringify(value) });
  }
  put<T>(path: string, value: unknown): Promise<T> {
    return this.request<T>(path, { method: "PUT", body: JSON.stringify({ value }) });
  }

  websocketUrl(): string {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    return `${protocol}//${window.location.host}/api/v1/ws/events`;
  }
}
