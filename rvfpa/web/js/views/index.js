/**
 * 导航名称与页面模块的对应表。
 * 应用入口根据当前导航项调用相应页面的render和bind函数。
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
