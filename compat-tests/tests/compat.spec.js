import { expect, test } from "@playwright/test";

test.describe("auth-client storage compatibility", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page.waitForFunction(
      () => window.compatReady === true || window.compatError,
    );
    const error = await page.evaluate(() => window.compatError);
    if (error) {
      throw new Error(error);
    }
    await page.evaluate(async () => {
      await window.compat.ready();
      await window.compat.clearStorage();
    });
  });

  test("Ed25519: JS -> Rust", async ({ page }) => {
    const { jsPrincipal, rustPrincipal } = await page.evaluate(async () => {
      await window.compat.jsGenerateKey("Ed25519");
      const jsPrincipal = await window.compat.jsStoredKeyPrincipal();
      const rustPrincipal = await window.compat.rustReadPrincipal("Ed25519");
      return { jsPrincipal, rustPrincipal };
    });

    expect(rustPrincipal).toBe(jsPrincipal);
  });

  test("Ed25519: Rust -> JS", async ({ page }) => {
    const { rustPrincipal, jsPrincipal } = await page.evaluate(async () => {
      const rustPrincipal = await window.compat.rustWriteKey("Ed25519");
      const jsPrincipal = await window.compat.jsStoredKeyPrincipal();
      return { rustPrincipal, jsPrincipal };
    });

    expect(jsPrincipal).toBe(rustPrincipal);
  });

  test("ECDSA: JS -> Rust", async ({ page }) => {
    const errorMessage = await page.evaluate(async () => {
      await window.compat.jsGenerateKey("ECDSA");
      try {
        await window.compat.rustReadPrincipal("ECDSA");
      } catch (error) {
        return String(error);
      }
      return null;
    });

    expect(errorMessage).toContain("extractable");
  });

  test("ECDSA: Rust -> JS", async ({ page }) => {
    const { rustPrincipal, jsPrincipal } = await page.evaluate(async () => {
      const rustPrincipal = await window.compat.rustWriteKey("ECDSA");
      const jsPrincipal = await window.compat.jsStoredKeyPrincipal();
      return { rustPrincipal, jsPrincipal };
    });

    expect(jsPrincipal).toBe(rustPrincipal);
  });
});
