#!/usr/bin/env node
// PatchPilot WebGate — axe-core accessibility scanner (jsdom, no browser needed).
//
// The UI arm of the verified-remediation engine: the *objective oracle* for the
// a11y gate, exactly as Semgrep/CodeQL are for the security gate. Given an HTML
// file (or string on stdin), it returns the list of axe-core accessibility
// VIOLATIONS as JSON. The a11y gate (harness/webgate.py) runs this on the
// original page (expect violations -> RED) and the patched page (expect the
// target rule gone -> GREEN) to prove a fix flipped fail -> pass.
//
// jsdom has no layout engine, so layout-dependent rules (color-contrast) are
// disabled here; use axe_scan_browser.mjs (Playwright) for those + screenshots.
//
// Usage:
//   node axe_scan.mjs <file.html> [--only rule1,rule2] [--quiet]
//   cat page.html | node axe_scan.mjs -            # read from stdin
//
// Output (stdout): JSON { source, violationCount, ruleCount, byRule, violations[] }
// Exit: 0 always when the scan ran (cleanliness is read from violationCount); 2 bad args; 3 axe error.

import fs from 'node:fs';
import { JSDOM } from 'jsdom';
import axe from 'axe-core';

function die(msg, code) { process.stderr.write(`[axe_scan] ${msg}\n`); process.exit(code); }

const args = process.argv.slice(2);
if (args.length < 1) die('usage: node axe_scan.mjs <file.html|-> [--only r1,r2] [--quiet]', 2);

const source = args[0];
let only = null;
let quiet = false;
for (let i = 1; i < args.length; i++) {
  if (args[i] === '--only') only = (args[++i] || '').split(',').map(s => s.trim()).filter(Boolean);
  else if (args[i] === '--quiet') quiet = true;
}

let html;
try {
  html = source === '-' ? fs.readFileSync(0, 'utf8') : fs.readFileSync(source, 'utf8');
} catch (e) {
  die(`cannot read ${source}: ${e.message}`, 2);
}

const dom = new JSDOM(html, { runScripts: 'outside-only', pretendToBeVisual: true });
const { window } = dom;

// Inject axe-core into the jsdom window so window.axe.run can walk this document.
try {
  window.eval(axe.source);
} catch (e) {
  die(`failed to inject axe-core into jsdom: ${e.message}`, 3);
}

const options = {
  // Layout-dependent rules don't work without a render engine -> turn off in jsdom.
  rules: { 'color-contrast': { enabled: false } },
};
if (only) options.runOnly = { type: 'rule', values: only };

window.axe
  .run(window.document, options)
  .then((results) => {
    const violations = results.violations.map((v) => ({
      id: v.id,
      impact: v.impact,
      help: v.help,
      helpUrl: v.helpUrl,
      nodes: v.nodes.map((n) => ({
        target: n.target,
        html: n.html,
        failureSummary: n.failureSummary,
      })),
    }));
    const byRule = {};
    for (const v of violations) byRule[v.id] = v.nodes.length;
    const out = {
      source,
      violationCount: violations.reduce((a, v) => a + v.nodes.length, 0),
      ruleCount: violations.length,
      byRule,
      violations: quiet ? undefined : violations,
    };
    process.stdout.write(JSON.stringify(out, null, 2) + '\n');
  })
  .catch((err) => die(`axe.run failed: ${err.message}`, 3));
