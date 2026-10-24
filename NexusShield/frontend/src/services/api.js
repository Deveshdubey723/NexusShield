const API_BASE = (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000").replace(/\/$/, "");

async function request(path, options = {}) {
  let response;
  try {
    response = await fetch(`${API_BASE}${path}`, options);
  } catch {
    throw new Error(`Cannot reach the NEXUS SHIELD API at ${API_BASE}. Start the backend and try again.`);
  }

  if (!response.ok) {
    let detail = `Request failed (${response.status})`;
    try {
      const payload = await response.json();
      if (typeof payload.detail === "string") {
        detail = payload.detail;
      } else if (Array.isArray(payload.detail)) {
        detail = payload.detail.map((issue) => {
          const field = Array.isArray(issue.loc) ? issue.loc.slice(1).join(".") : "";
          return `${field ? `${field}: ` : ""}${issue.msg || "Invalid value."}`;
        }).join(" ");
      }
    } catch {
      // The API may return a non-JSON error response.
    }
    throw new Error(detail);
  }
  return response.status === 204 ? null : response.json();
}

export const api = {
  analyzeMessage: (text, saveContent = false) => request("/api/analyze/message", json({ text, save_content: saveContent })),
  analyzeUrl: (url, saveContent = false) => request("/api/analyze/url", json({ url, save_content: saveContent })),
  analyzeEmail: (data, saveContent = false) => request("/api/analyze/email", json({ ...data, save_content: saveContent })),
  history: () => request("/api/history"),
  clearHistory: () => request("/api/history", { method: "DELETE" }),
  stats: () => request("/api/dashboard/stats"),
  settings: () => request("/api/settings"),
  updateSettings: (data) => request("/api/settings", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  }),
  notes: () => request("/api/notes"),
  createNote: (note) => request("/api/notes", json({ note })),
  deleteNote: (id) => request(`/api/notes/${encodeURIComponent(id)}`, { method: "DELETE" }),
  uploadDocument: (file) => {
    const form = new FormData();
    form.append("file", file);
    return request("/api/documents/upload", { method: "POST", body: form });
  },
  documents: () => request("/api/documents"),
  deleteDocument: (id) => request(`/api/documents/${encodeURIComponent(id)}`, { method: "DELETE" }),
  searchDocuments: (query) => request("/api/documents/search", json({ query })),
};

function json(data) {
  return {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  };
}
