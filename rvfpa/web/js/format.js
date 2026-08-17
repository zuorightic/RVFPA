export function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

export function formatBytes(value, decimals = 2) {
  const number = Number(value || 0);
  if (!Number.isFinite(number)) return "-";
  if (Math.abs(number) < 1024) return `${Math.round(number)} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let scaled = number;
  let unit = "B";
  for (const candidate of units) {
    scaled /= 1024;
    unit = candidate;
    if (Math.abs(scaled) < 1024) break;
  }
  return `${scaled.toFixed(decimals)} ${unit}`;
}

export function formatNumber(value) {
  return new Intl.NumberFormat("zh-CN").format(Number(value || 0));
}

export function formatPercent(value, decimals = 2) {
  const number = Number(value || 0);
  return `${number.toFixed(decimals)}%`;
}

export function formatAddress(value) {
  const number = Number(value || 0);
  return `0x${number.toString(16).padStart(number > 0xffffffff ? 16 : 8, "0")}`;
}

export function formatDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

export function severityLabel(value) {
  return { error: "错误", warning: "警告", info: "提示" }[value] || value;
}

export function deltaText(value, suffix = "") {
  const number = Number(value || 0);
  const sign = number > 0 ? "+" : "";
  return `${sign}${formatNumber(number)}${suffix}`;
}

export function deltaClass(value) {
  const number = Number(value || 0);
  if (number > 0) return "delta-positive";
  if (number < 0) return "delta-negative";
  return "delta-neutral";
}

export function downloadNameFromHeader(response, fallback) {
  const header = response.headers.get("content-disposition") || "";
  const match = /filename="([^"]+)"/.exec(header);
  return match?.[1] || fallback;
}

export function clamp(value, minimum, maximum) {
  return Math.min(maximum, Math.max(minimum, Number(value || 0)));
}

