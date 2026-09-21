import assert from "node:assert/strict";
import { chromium } from "playwright";

const base = process.argv[2];
const cases = await (await fetch(`${base}/cases`)).json();
const browser = await chromium.launch({ headless: true });
try {
  for (const name of cases) {
    const page = await browser.newPage();
    await page.addInitScript(() => { window.CAP_DEBUG = true; });
    const logs = [];
    page.on("console", (message) => logs.push(message.text()));
    page.on("pageerror", (error) => logs.push(error.message));
    page.setDefaultTimeout(45000);
    // Keep the test independent of public CDNs: widget and WASM are pinned locally.
    await page.route("**/*", (route) => {
      const url = route.request().url();
      return url.startsWith(base + "/") || url.startsWith("blob:") || url.startsWith("data:")
        ? route.continue()
        : route.abort();
    });
    try {
      await page.goto(base);
      const outcome = await page.evaluate(async (name) => {
        await customElements.whenDefined("cap-widget");
        const widget = document.createElement("cap-widget");
        widget.setAttribute("data-cap-api-endpoint", `/api/${name}/`);
        widget.setAttribute("data-cap-worker-count", "1");
        widget.setAttribute("data-cap-disable-haptics", "");
        document.body.appendChild(widget);
        return await Promise.race([
          widget.solve(),
          new Promise((_, reject) => setTimeout(() => reject(new Error("widget solve timed out")), 40000)),
        ]);
      }, name);
      assert.equal(outcome?.success, true, `${name}: ${JSON.stringify(outcome)}`);
      assert.equal(typeof outcome.token, "string", name);
      const check = await fetch(`${base}/api/${name}/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: outcome.token }),
      });
      assert.equal(check.status, 204, `${name}: ${await check.text()}`);
      console.log(`PASS ${name}: widget solved, redeemed, token consumed once`);
    } catch (error) {
      console.error(`FAIL ${name}\n${logs.join("\n")}`);
      throw error;
    } finally {
      await page.close();
    }
  }
} finally {
  await browser.close();
}
