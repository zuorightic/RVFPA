/**
 * 业务视图注册表：集中声明导航名称与页面模块之间的对应关系，
 * 由应用入口按当前状态选择渲染和绑定函数。
 */

import * as overview from "./overview.js";
import * as versions from "./versions.js";
import * as sections from "./sections.js";
import * as symbols from "./symbols.js";
import * as instructions from "./instructions.js";
import * as functions from "./functions.js";
import * as release from "./release.js";
import * as policy from "./policy.js";
import * as compare from "./compare.js";
import * as reports from "./reports.js";
import * as settings from "./settings.js";

export const views = Object.freeze({
  overview,
  versions,
  sections,
  symbols,
  instructions,
  functions,
  release,
  policy,
  compare,
  reports,
  settings,
});
