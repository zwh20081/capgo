import { validateChallenge } from "capjs-core";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
const { verifyInstrumentationResult } = await import(pathToFileURL(createRequire(import.meta.url).resolve("capjs-core").replace(/index.js$/, "instrumentation.js")).href);
import fs from "node:fs";
const v = JSON.parse(fs.readFileSync("go-vectors.json", "utf8"));
const secret = Buffer.from(v.secretHex, "hex");
let fails = 0;
const check = (name, r, expectSuccess = true, reason) => {
  const ok = expectSuccess ? r.success === true : (r.success === false && (!reason || r.reason === reason));
  console.log((ok ? "PASS" : "FAIL"), name, JSON.stringify({ success: r.success, reason: r.reason, scope: r.scope }));
  if (!ok) fails++;
};
// format 1 stateless
let r = await validateChallenge(secret, { token: v.format1.challenge.token, solutions: v.format1.solutions }, { scope: "login" });
check("format1 stateless validated by capjs-core", r);
r = await validateChallenge(secret, { token: v.format1.challenge.token, solutions: v.format1.solutions }, { scope: "other" });
check("format1 wrong scope", r, false, "scope_mismatch");
// format 2
r = await validateChallenge(secret, { token: v.format2.challenge.token, solutions: v.format2.solutions }, { scope: "signup" });
check("format2 pow+rsw validated by capjs-core", r);
const badSol = structuredClone(v.format2.solutions); badSol[2].y = "1";
r = await validateChallenge(secret, { token: v.format2.challenge.token, solutions: badSol }, { scope: "signup" });
check("format2 wrong rsw", r, false, "invalid_solution");
// format1 with instrumentation: missing instr should be instr_missing
r = await validateChallenge(secret, { token: v.format1instr.challenge.token, solutions: v.format1instr.solutions }, { scope: "fb" });
check("format1instr missing instr", r, false, "instr_missing");
// verify Go instr meta via capjs-core verifier with self-consistent state
for (const it of v.instrumentation) {
  const state = {}; it.meta.vars.forEach((n, i) => state[n] = it.meta.expectedVals[i]);
  const ok = verifyInstrumentationResult(it.meta, { i: it.meta.id, state, ts: 1 });
  check(`instr meta level=${it.level} block=${it.block} accepted by capjs-core verifier`, { success: ok.valid, reason: ok.reason });
}
console.log(fails ? `FAILURES: ${fails}` : "ALL PASS");
process.exit(fails ? 1 : 0);
