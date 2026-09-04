import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiClient } from "./api";

describe("ApiClient", () => {
  afterEach(() => vi.unstubAllGlobals());
  it("sends the in-memory bearer token", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ ok: true }) });
    vi.stubGlobal("fetch", fetchMock);
    await new ApiClient("secret", "http://sentinel.test/api/v1").get("/dashboard");
    expect(fetchMock.mock.calls[0][1].headers.Authorization).toBe("Bearer secret");
  });
  it("reports API failures", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 401 }));
    await expect(new ApiClient("bad", "").get("/dashboard")).rejects.toThrow("401");
  });
});
