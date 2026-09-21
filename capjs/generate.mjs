import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { randomInt } from "node:crypto";
import { deflateRawSync, inflateRawSync } from "node:zlib";

const options = JSON.parse(fs.readFileSync(0, "utf8"));
const require = createRequire(path.join(process.cwd(), "package.json"));
const entry = require.resolve("capjs-core");
const coreRequire = createRequire(entry);
// Resolve from core's location, matching its dynamic imports even with pnpm.
if (options.obfuscationLevel >= 4) {
  await import(pathToFileURL(coreRequire.resolve("esbuild")).href);
}
let obfuscator;
if (options.obfuscationLevel >= 8) {
  const mod = await import(pathToFileURL(coreRequire.resolve("javascript-obfuscator")).href);
  obfuscator = mod.default ?? mod;
}
const { generateInstrumentation } = await import(
  pathToFileURL(path.join(path.dirname(entry), "instrumentation.js")).href
);
const result = await generateInstrumentation(obfuscator ? { ...options, obfuscationLevel: 3 } : options);
if (obfuscator) {
  let script = inflateRawSync(Buffer.from(result.instrumentation, "base64")).toString("utf8");
  // Core 0.1.2 constructs a local variable's name at runtime for direct eval.
  // Renaming it or wrapping eval in a control-flow helper breaks the probe.
  // Preserve that block while applying the upstream profile to the rest.
  const probe = script.match(/try \{ var ([a-z][a-z0-9]*) = \d+; var [a-z][a-z0-9]* = '[^']*'; var [a-z][a-z0-9]* = '[^']*';[\s\S]*?\} catch \{ return null \}/);
  if (!probe) throw new Error("capjs: unsupported upstream eval probe");
  script = script.replace(probe[0], `/* javascript-obfuscator:disable */${probe[0]}/* javascript-obfuscator:enable */`);
  const level = options.obfuscationLevel;
  const output = obfuscator.obfuscate(script, {
    compact: true,
    ignoreRequireImports: true,
    identifierNamesGenerator: "mangled-shuffled",
    reservedNames: [`^${probe[1]}$`],
    stringArray: true,
    stringArrayThreshold: 0.75,
    stringArrayEncoding: ["rc4"],
    splitStrings: true,
    splitStringsChunkLength: randomInt(3, 16),
    controlFlowFlattening: true,
    controlFlowFlatteningThreshold: level >= 9 ? 0.75 : 0.4,
    deadCodeInjection: true,
    deadCodeInjectionThreshold: level >= 9 ? 0.3 : 0.1,
    selfDefending: level >= 9,
    debugProtection: level >= 10,
    disableConsoleOutput: level >= 10,
  }).getObfuscatedCode();
  result.instrumentation = deflateRawSync(Buffer.from(output), { level: 1 }).toString("base64");
}
process.stdout.write(JSON.stringify(result));
