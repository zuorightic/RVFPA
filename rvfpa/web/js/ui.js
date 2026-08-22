/**
 * 提示消息、模态框、页面标题和空状态等共用界面组件。
 * 业务页面直接调用这些组件，不必各自实现一遍相同交互。
 */

import { escapeHtml } from "./format.js";

const modalRoot = document.querySelector("#modal-root");
const toastRoot = document.querySelector("#toast-root");

export function showToast(message, type = "info", duration = 4200) {
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.textContent = message;
  toastRoot.append(toast);
  window.setTimeout(() => toast.remove(), duration);
}

export function showModal({ title, body, width = "normal", submitText = "确认", onSubmit }) {
  const backdrop = document.createElement("div");
  backdrop.className = "modal-backdrop";
  backdrop.innerHTML = `
    <section class="modal ${width === "wide" ? "wide" : ""}" role="dialog" aria-modal="true">
      <header class="modal-header">
        <h2>${escapeHtml(title)}</h2>
        <button class="modal-close" type="button" title="关闭" aria-label="关闭">×</button>
      </header>
      <form>
        <div class="modal-body">${body}</div>
        <footer class="modal-footer">
          <button class="secondary-button" type="button" data-action="cancel">取消</button>
          <button class="primary-button" type="submit">${escapeHtml(submitText)}</button>
        </footer>
      </form>
    </section>`;
  const close = () => {
    document.removeEventListener("keydown", onKeyDown);
    backdrop.remove();
  };
  const onKeyDown = (event) => {
    if (event.key === "Escape") close();
  };
  backdrop.querySelector(".modal-close").addEventListener("click", close);
  backdrop.querySelector('[data-action="cancel"]').addEventListener("click", close);
  backdrop.addEventListener("click", (event) => {
    if (event.target === backdrop) close();
  });
  backdrop.querySelector("form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = event.submitter || backdrop.querySelector('[type="submit"]');
    submit.disabled = true;
    try {
      const shouldClose = await onSubmit?.(new FormData(event.currentTarget), event.currentTarget);
      if (shouldClose !== false) close();
    } catch (error) {
      showToast(error.message || String(error), "error");
    } finally {
      submit.disabled = false;
    }
  });
  document.addEventListener("keydown", onKeyDown);
  modalRoot.append(backdrop);
  const firstInput = backdrop.querySelector("input, select, textarea, button");
  firstInput?.focus();
  return { element: backdrop, close };
}

export function confirmAction(message, confirmText = "继续") {
  return new Promise((resolve) => {
    const control = showModal({
      title: "确认操作",
      body: `<p style="margin:0;line-height:22px;color:var(--ink-secondary)">${escapeHtml(message)}</p>`,
      submitText: confirmText,
      onSubmit: () => {
        resolve(true);
        return true;
      },
    });
    control.element.querySelector('[data-action="cancel"]').addEventListener("click", () => resolve(false), { once: true });
    control.element.querySelector(".modal-close").addEventListener("click", () => resolve(false), { once: true });
  });
}

export function pageHeader(title, subtitle, actions = "") {
  return `
    <header class="page-header">
      <div><h1>${escapeHtml(title)}</h1><p>${escapeHtml(subtitle)}</p></div>
      <div class="page-actions">${actions}</div>
    </header>`;
}

export function emptyState(title, message, action = "") {
  return `
    <section class="empty-state">
      <div class="empty-symbol">RV</div>
      <h2>${escapeHtml(title)}</h2>
      <p>${escapeHtml(message)}</p>
      ${action}
    </section>`;
}
