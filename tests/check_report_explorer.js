/* 선택적 Node 검증. 저장된 근거로 DOM과 탐색 동작을 모의한다. */
"use strict";
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");
const assert = require("node:assert/strict");
const dir = path.join(__dirname,"../webrecon");
class Element {
  constructor() {
    this.children = []; this.listeners = {}; this.dataset = {}; this.textContent = "";
    this.attributes = {}; this.value = "";
  }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  setAttribute(key,value) { this.attributes[key] = value; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  focus() {}
  querySelector() { return null; }
  descendants() { return [this,...this.children.flatMap(el => el.descendants())]; }
}
const url = "https://example.invalid";
const edge = (to,via,at,method="") => ({to,via,at,method});
const nodes = [
  {kind:"page",label:"사용자",address:url+"/",open:true,edges:[edge(1,"script.src"),edge(0,"a.href")]},
  {kind:"js",label:url+"/app.js",address:url+"/app.js",open:true,edges:[edge(2,"선언",[1,10]),edge(4,"선언",[5,10]),edge(5,"선언",[1,15])]},
  {kind:"function",label:"load()",unit:1,at:[1,10],uses:[[6,3]],edges:[edge(3,"fetch",[2,3],"GET"),edge(5,"변수 사용",[2,10])]},
  {kind:"api",label:url+"/api/users",address:url+"/api/users",edges:[]},
  {kind:"function",label:"start()",unit:1,at:[5,10],edges:[edge(2,"직접 호출",[6,3])]},
  {kind:"variable",label:"id",unit:1,at:[1,15],edges:[]}
];
for (let i=0;i<45;i++) nodes.push({kind:"page",label:"page "+i,address:url+"/p"+i,edges:[]});
nodes.forEach((n,i) => { n.id=i; });
const ids = new Map(Array.from(fs.readFileSync(path.join(dir,"report_template.html"),"utf8").matchAll(/id="([^"]+)"/g),
  m => [m[1],new Element()]));
const get = key => ids.get("ex-"+key);
const named = (parent,label) => parent.descendants().find(el => el.textContent === label);
const pick = label => get("tree").descendants().find(el => el.dataset.pick &&
  el.children.some(child => child.textContent === label)).listeners.click();
const opened = [];
const window = {open:(...args) => opened.push(args)};
ids.get("explorer-data").textContent = JSON.stringify(nodes);
const document = {getElementById:id => ids.get(id), createElement:() => new Element()};
vm.runInNewContext(fs.readFileSync(path.join(dir,"report_explorer.js"),"utf8"),
  {document, window, URL});

function test() {
  assert.equal(get("list").children.length,40);
  assert.ok(named(get("tree"),"/api/users"));
  assert.ok(get("tree").descendants().some(el => el.textContent.includes("이미 표시한 경로")));
  assert.equal(opened.length,0);
  named(get("detail"),"원본 새 창 ↗").listeners.click();
  assert.deepEqual(opened,[[url+"/","_blank","noopener,noreferrer"]]);
  get("more").listeners.click(); assert.equal(get("list").children.length,46);
  get("filter").value = "사용자"; get("filter").listeners.input(); assert.equal(get("list").children.length,1);
  get("filter").value = ""; get("filter").listeners.input();

  pick("load()");
  assert.ok(named(get("detail"),"이 함수를 호출한 곳 · 1"));
  named(get("detail"),"원본 JS 새 창 ↗").listeners.click();
  assert.deepEqual(opened[1],[url+"/app.js","_blank","noopener,noreferrer"]);
  assert.ok(named(get("detail"),"사용하는 변수 · 1"));
  assert.ok(named(get("detail"),url+"/app.js · 1행 10열"));
  named(get("detail"),"start()").listeners.click();
  assert.ok(named(get("detail"),"호출하는 함수 · 1"));
  get("kind").value = "variable"; get("kind").listeners.change();
  assert.equal(get("direction").value,"in");
  assert.ok(named(get("detail"),"변수 사용처 · 1"));
  assert.ok(named(get("tree"),"load()"));
  get("kind").value = "api"; get("kind").listeners.change();
  assert.ok(!named(get("detail"),"원본 새 창 ↗"));
  assert.ok(named(get("tree"),"사용자"));
  assert.ok(!ids.has("ex-file") && !ids.has("ex-code"));
  assert.equal(opened.length,2);
}
test();
console.log("Passed: explorer tree, cycles, paging, original link, caller/callee, variable uses, declaration location.");
