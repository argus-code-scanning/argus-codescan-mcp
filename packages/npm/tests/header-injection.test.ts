import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { runNativeSast } from "../src/scanners/native-sast.js";

// Same cases as argus-languages tests/test_header_injection_rules.py (#187).
async function ids(name: string, code: string): Promise<string[]> {
  const dir = mkdtempSync(join(tmpdir(), "argus-hdr-"));
  writeFileSync(join(dir, name), `${code}\n`);
  return (await runNativeSast(dir)).findings.map((f) => f.ruleId ?? "").filter((id) => /header|email|mail|disposition/.test(id));
}

describe("header and email injection (#187)", () => {
  it.each([
    ["app.js", 'res.setHeader("X-User", req.body.user);', "js-response-header-from-request"],
    ["mail.js", "transporter.sendMail({ to: req.body.to, subject: s, text });", "js-email-from-request"],
    ["contact.php", "<?php mail($_POST['to'], $_POST['subject'], $body, 'From: ' . $_POST['from']);", "php-mail-header-injection"],
    ["app.py", 'resp.headers["X-Name"] = request.args["name"]', "py-response-header-from-request"],
    ["A.java", 'response.setHeader("X-Name", request.getParameter("name"));', "java-response-header-from-request"],
  ])("%s: flags %s", async (name, code, rule) => {
    expect(await ids(name, code)).toContain(rule);
  });

  it.each([
    ["app.js", 'res.setHeader("Location", req.query.next);'],
    ["app.js", 'res.setHeader("X-Q", encodeURIComponent(req.query.q));'],
    ["mail.js", "transporter.sendMail({ to: user.email, subject: 'Welcome' });"],
    ["app.py", 'resp.headers["X-Version"] = VERSION'],
  ])("%s: ignores %s", async (name, code) => {
    expect(await ids(name, code)).toEqual([]);
  });
});
