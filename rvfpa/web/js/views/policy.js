/**
 * 准入策略页。用户可以编辑JSON规则、执行评估，并查看每条规则的结果和证据。
 */

import { escapeHtml, formatNumber } from "../format.js";
import { emptyState, pageHeader } from "../ui.js";

const DEFAULT_POLICY = {
  name: "项目发布准入策略",
  limits: {
    file_bytes: "2M",
    code_bytes: "512K",
    runtime_bytes: "256K",
  },
  region_usage_percent: {
    FLASH: 85,
    RAM: 85,
  },
  required_extensions: ["I"],
  forbidden_extensions: [],
  allowed_abis: ["lp64", "ilp32"],
  required_sections: [".text"],
  forbidden_sections: [".note.GNU-stack"],
  max_diagnostics: {
    error: 0,
    warning: 5,
  },
  max_decode_failure_percent: 1,
  max_function_complexity: 40,
  forbidden_string_patterns: [
    "password\\s*=",
    "BEGIN RSA PRIVATE KEY",
  ],
};

function resultRows(results) {
  return results.map((item) => `
    <tr>
      <td><span class="badge ${item.status === "pass" ? "green" : "red"}">${item.status === "pass" ? "通过" : "失败"}</span></td>
      <td><strong>${escapeHtml(item.title)}</strong><small class="cell-note">${escapeHtml(item.rule_id)}</small></td>
      <td>${escapeHtml(item.summary)}</td>
      <td class="mono policy-value">${escapeHtml(JSON.stringify(item.expected))}</td>
      <td class="mono policy-value">${escapeHtml(JSON.stringify(item.actual))}</td>
      <td>${(item.evidence || []).slice(0, 4).map((value) => `<div>${escapeHtml(value)}</div>`).join("") || "-"}</td>
    </tr>`).join("");
}

function resultPanel(evaluation) {
  if (!evaluation) {
    return `<section class="panel policy-result"><div class="panel-body">${emptyState("尚未执行策略", "编辑JSON后点击执行评估。")}</div></section>`;
  }
  return `
    <section class="release-summary ${evaluation.status === "pass" ? "pass" : "fail"}">
      <div><span>策略结果</span><strong>${evaluation.status === "pass" ? "全部通过" : "存在失败规则"}</strong></div>
      <p>${escapeHtml(evaluation.policy_name)} · ${formatNumber(evaluation.passed)}项通过 · ${formatNumber(evaluation.failed)}项失败</p>
    </section>
    <div class="data-table-wrap"><table class="data-table">
      <thead><tr><th>状态</th><th>规则</th><th>说明</th><th>期望</th><th>实际</th><th>证据</th></tr></thead>
      <tbody>${resultRows(evaluation.results || [])}</tbody>
    </table></div>`;
}

export function render(context) {
  if (!context.state.analysis || !context.state.snapshotId) {
    return `${pageHeader("准入策略", "按项目预算和交付规则自动评估当前固件。")}${emptyState("没有分析数据", "请先选择一个固件版本。")}`;
  }
  const stored = sessionStorage.getItem("rvfpa-policy");
  const policyText = stored || JSON.stringify(DEFAULT_POLICY, null, 2);
  return `
    ${pageHeader("准入策略", "使用JSON配置体积、区域、ABI、扩展、段、诊断、复杂度和字符串规则。")}
    <section class="policy-layout">
      <section class="panel policy-editor">
        <header class="panel-header"><h2>策略JSON</h2><span>仅在本机浏览器会话保存</span></header>
        <div class="panel-body">
          <textarea id="policy-json" class="policy-textarea mono" spellcheck="false">${escapeHtml(policyText)}</textarea>
          <div class="policy-actions">
            <button id="policy-reset" class="command-button" type="button">恢复示例</button>
            <span class="spacer"></span>
            <button id="policy-run" class="primary-button" type="button">执行评估</button>
          </div>
        </div>
      </section>
      <div id="policy-output">${resultPanel(null)}</div>
    </section>`;
}

export function bind(context, root) {
  const textarea = root.querySelector("#policy-json");
  const output = root.querySelector("#policy-output");
  const run = root.querySelector("#policy-run");
  const reset = root.querySelector("#policy-reset");
  if (!textarea || !run) return;

  reset.addEventListener("click", () => {
    textarea.value = JSON.stringify(DEFAULT_POLICY, null, 2);
    sessionStorage.removeItem("rvfpa-policy");
  });
  run.addEventListener("click", async () => {
    let policy;
    try {
      policy = JSON.parse(textarea.value);
    } catch (error) {
      context.showToast(`策略JSON格式错误：${error.message}`, "error");
      return;
    }
    run.disabled = true;
    run.textContent = "评估中";
    try {
      sessionStorage.setItem("rvfpa-policy", textarea.value);
      const payload = await context.api.evaluatePolicy(context.state.snapshotId, policy);
      output.innerHTML = resultPanel(payload.evaluation);
      context.showToast(payload.evaluation.status === "pass" ? "策略评估通过" : "策略存在失败规则", payload.evaluation.status === "pass" ? "success" : "error");
    } catch (error) {
      context.showToast(error.message, "error");
    } finally {
      run.disabled = false;
      run.textContent = "执行评估";
    }
  });
}
