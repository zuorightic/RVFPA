const JSON_HEADERS = Object.freeze({ "Content-Type": "application/json" });

export class ApiError extends Error {
  constructor(message, code = "api_error", status = 0) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
  }
}

async function request(path, options = {}) {
  const response = await fetch(path, {
    cache: "no-store",
    ...options,
  });
  const mediaType = response.headers.get("content-type") || "";
  let payload = null;
  if (mediaType.includes("application/json")) {
    payload = await response.json();
  } else {
    payload = await response.text();
  }
  if (!response.ok) {
    const error = payload?.error || {};
    throw new ApiError(
      error.message || response.statusText || "请求失败",
      error.code || "http_error",
      response.status,
    );
  }
  return payload;
}

export const api = {
  health() {
    return request("/api/health");
  },

  listProjects() {
    return request("/api/projects");
  },

  getProject(projectId) {
    return request(`/api/projects/${projectId}`);
  },

  createProject(payload) {
    return request("/api/projects", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(payload),
    });
  },

  updateProject(projectId, payload) {
    return request(`/api/projects/${projectId}`, {
      method: "PUT",
      headers: JSON_HEADERS,
      body: JSON.stringify(payload),
    });
  },

  listSnapshots(projectId) {
    return request(`/api/projects/${projectId}/snapshots`);
  },

  createSnapshot(projectId, payload) {
    return request(`/api/projects/${projectId}/snapshots`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(payload),
    });
  },

  importDemo(projectId) {
    return request(`/api/projects/${projectId}/demo`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: "{}",
    });
  },

  getSnapshot(snapshotId) {
    return request(`/api/snapshots/${snapshotId}`);
  },

  getAnalysis(snapshotId) {
    return request(`/api/snapshots/${snapshotId}/analysis`);
  },

  compare(baselineId, targetId) {
    const query = new URLSearchParams({
      baseline: String(baselineId),
      target: String(targetId),
    });
    return request(`/api/diff?${query}`);
  },

  reportUrl(snapshotId, format) {
    const query = new URLSearchParams({ format });
    return `/api/snapshots/${snapshotId}/report?${query}`;
  },

  evaluatePolicy(snapshotId, policy) {
    return request(`/api/snapshots/${snapshotId}/policy`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(policy),
    });
  },
};

export function readFileAsBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new ApiError(`无法读取文件：${file.name}`, "file_read_error"));
    reader.onload = () => {
      const result = String(reader.result || "");
      const comma = result.indexOf(",");
      resolve(comma >= 0 ? result.slice(comma + 1) : result);
    };
    reader.readAsDataURL(file);
  });
}
