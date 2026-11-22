/* 선택적인 개발 검증: 이미 설치된 Node로 실행한다. 제품/필수 unittest 의존성이 아니다.
   실제 브라우저 대신 DOM 계약·탭·검색·분할 상태 전환만 검증한다. */
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const assert = require("node:assert/strict");

function element(dataset = {}, attributes = {}) {
  return {dataset, attributes, id: attributes.id, value: "", hidden: false, disabled: false,
    textContent: "", listeners: {}, tabIndex: 0,
    addEventListener(type, callback) { this.listeners[type] = callback; },
    setAttribute(name, value) { this.attributes[name] = value; },
    getAttribute(name) { return this.attributes[name]; },
    focus() { this.focused = true; }};
}
const names = ["document", "endpoint", "resource", "pattern", "variable", "js-diagnostic", "request", "diagnostic"];
const tabs = names.map(name => element({}, {id: "tab-" + name, href: "#" + name + "-section"}));
const panels = names.map(name => element({}, {id: name + "-section"}));
const bar = element();
function inventory(identifier, filterNames, entries) {
  const search = element(), count = element(), empty = element(), reset = element(), pager = element();
  const size = element(), previous = element(), next = element(), position = element();
  size.value = "50"; pager.hidden = true;
  const filters = filterNames.map(filter => element({filter}));
  const rows = entries.map(entry => Object.assign(element(entry.dataset), {textContent: entry.text}));
  return Object.assign(element({inventory: identifier}), {search, count, empty, reset, pager, size, previous, next, position, filters, rows,
    querySelector(selector) {
      const nodes = {"[data-search]": search, "[data-count]": count, "[data-empty]": empty, "[data-reset]": reset,
        "[data-pagination]": pager, "[data-page-size]": size, "[data-previous]": previous, "[data-next]": next, "[data-page-position]": position};
      if (nodes[selector]) return nodes[selector];
      if (selector === '[data-filter="category"]') return filters.find(item => item.dataset.filter === "category");
      throw Error(selector);
    },
    querySelectorAll(selector) {
      if (selector === "[data-filter]") return filters;
      if (selector === "tbody > tr") return rows;
      throw Error(selector);
    }});
}
const entries = Array.from({length: 123}, (_, index) => ({text: "/page/" + index,
  dataset: {category: index % 2 ? "api authentication" : "unknown", domain: "example.invalid",
    method: index % 2 ? "declared:POST" : "observed:GET", visit: "not_visited", scope: "inside"}}));
const endpoints = inventory("endpoints", ["category", "domain", "method", "visit", "scope"], entries);
const resources = inventory("resources", ["resource"], [
  {text: "/app.js", dataset: {resource: "JavaScript"}}, {text: "/style.css", dataset: {resource: "CSS"}}]);
const emptyInventory = inventory("documents", [], []);
const variables = inventory("variables", ["resolution", "source"], [
  {text: "userId", dataset: {resolution: "unresolved", source: "local:input.js"}},
  {text: "path", dataset: {resolution: "resolved", source: "local:input.js"}}]);
const inventories = [endpoints, resources, emptyInventory, variables];
const chip = element({category: "api"});
const window = {location: {hash: ""}, listeners: {}, addEventListener(type, fn) { this.listeners[type] = fn; }};
const document = {
  querySelector(selector) { if (selector === "[data-report-tabs]") return bar; throw Error(selector); },
  querySelectorAll(selector) {
    const values = {"[data-report-tab]": tabs, "[data-report-panel]": panels,
      "[data-inventory]": inventories, "[data-category]": [chip]};
    if (values[selector]) return values[selector];
    throw Error(selector);
  }
};
vm.runInNewContext(fs.readFileSync(path.join(__dirname, "../webrecon/report_ui.js"), "utf8"), {document, window, Map, Set, Array});
const visible = item => item.rows.filter(row => !row.hidden);
const event = key => ({key, preventDefault() { this.prevented = true; }});
assert.equal(panels.filter(panel => !panel.hidden)[0].id, "document-section");
assert.equal(tabs[0].attributes["aria-selected"], "true");
tabs[0].listeners.keydown(event("ArrowRight"));
assert.equal(window.location.hash, "endpoint-section");
assert.equal(panels.filter(panel => !panel.hidden)[0].id, "endpoint-section");
assert.equal(tabs[1].tabIndex, 0);
tabs[1].listeners.keydown(event("End"));
assert.equal(panels.filter(panel => !panel.hidden)[0].id, "diagnostic-section");
tabs[7].listeners.keydown(event("Home"));
assert.equal(panels.filter(panel => !panel.hidden)[0].id, "document-section");
window.location.hash = "#resource-section";
window.listeners.hashchange();
assert.equal(panels.filter(panel => !panel.hidden)[0].id, "resource-section");
assert.equal(visible(endpoints).length, 50);
assert.equal(endpoints.position.textContent, "1 / 3 페이지");
assert.equal(endpoints.previous.disabled, true);
endpoints.next.listeners.click(); endpoints.next.listeners.click();
assert.equal(visible(endpoints).length, 23);
assert.equal(endpoints.next.disabled, true);
endpoints.previous.listeners.click();
assert.equal(visible(endpoints)[0].textContent, "/page/50");
endpoints.search.value = "no-such-path"; endpoints.search.listeners.input();
assert.equal(visible(endpoints).length, 0);
assert.equal(endpoints.empty.hidden, false);
assert.equal(endpoints.position.textContent, "0 / 0 페이지");
assert.equal(endpoints.next.disabled, true);
endpoints.reset.listeners.click();
assert.equal(visible(endpoints).length, 50);
endpoints.size.value = "100"; endpoints.size.listeners.change();
assert.equal(visible(endpoints).length, 100);
chip.listeners.click();
assert.equal(endpoints.count.textContent, "61 / 123개 검색됨");
assert.equal(panels.filter(panel => !panel.hidden)[0].id, "endpoint-section");
assert.equal(endpoints.rows.filter(row => row.dataset.matches === "true").length, 61);
const method = endpoints.filters.find(item => item.dataset.filter === "method");
method.value = "observed:GET"; method.listeners.change();
assert.equal(visible(endpoints).length, 0);
resources.filters[0].value = "JavaScript"; resources.filters[0].listeners.change();
assert.deepEqual(visible(resources).map(row => row.textContent), ["/app.js"]);
variables.filters[0].value = "unresolved"; variables.filters[0].listeners.change();
assert.deepEqual(visible(variables).map(row => row.textContent), ["userId"]);
assert.equal(emptyInventory.empty.hidden, false);
assert.equal(emptyInventory.next.disabled, true);
assert.equal(emptyInventory.previous.disabled, true);
console.log("Passed: tabs/keyboard/hash, 123-row pagination, search/reset/empty state, combined filters, resource types, variable status, print matches (DOM simulation only).");
