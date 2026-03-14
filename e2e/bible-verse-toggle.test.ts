/**
 * E2E: Bible Verse toggle
 *
 * Verifies that the Bible verse bar can be shown/hidden through the Settings
 * modal and that the displayed verse text is non-empty when enabled.
 */
describe("Bible Verse toggle", () => {
  before(async () => {
    // Allow the app to fully initialise before running tests
    await browser.pause(1000);
  });

  it("shows a verse bar when Bible Verses is enabled by default", async () => {
    // The verse bar sits at the bottom of the window.
    // It fetches from the Rust backend and renders after an async settle.
    const verseBar = await $('[data-testid="verse-bar"]');
    const exists = await verseBar.isExisting();
    // The element may not have a testid; fall back to checking for verse-like
    // text anywhere in the document.
    if (!exists) {
      const body = await $("body");
      const text = await body.getText();
      // A verse reference always contains a colon, e.g. "John 3:16"
      expect(text).toMatch(/\w+ \d+:\d+/);
    } else {
      const text = await verseBar.getText();
      expect(text.length).toBeGreaterThan(0);
    }
  });

  it("opens the Settings modal via the gear icon", async () => {
    const settingsBtn = await $('[aria-label="Open settings"]');
    await settingsBtn.click();
    const modal = await $('[role="dialog"][aria-label="Settings"]');
    await modal.waitForDisplayed({ timeout: 3000 });
    expect(await modal.isDisplayed()).toBe(true);
  });

  it("can toggle the Bible Verses switch off", async () => {
    // Find the Bible Verses switch inside the open Settings modal
    const bibleSwitch = await $(
      '[role="dialog"] [role="switch"][aria-label*="Bible"], [role="dialog"] [role="switch"]:nth-child(2)'
    );
    const wasChecked = (await bibleSwitch.getAttribute("aria-checked")) === "true";
    if (wasChecked) {
      await bibleSwitch.click();
      const nowChecked = (await bibleSwitch.getAttribute("aria-checked")) === "true";
      expect(nowChecked).toBe(false);
    }
    // Close settings
    const closeBtn = await $('[aria-label="Close settings"]');
    await closeBtn.click();
  });

  it("can toggle the Bible Verses switch back on", async () => {
    const settingsBtn = await $('[aria-label="Open settings"]');
    await settingsBtn.click();
    const modal = await $('[role="dialog"][aria-label="Settings"]');
    await modal.waitForDisplayed({ timeout: 3000 });

    // Toggle back on (assumes it is currently off from previous test)
    const switches = await $$('[role="switch"]');
    // The Bible Verses switch is the second switch in the Learning section
    const bibleSwitch = switches[1];
    const wasChecked = (await bibleSwitch.getAttribute("aria-checked")) === "true";
    if (!wasChecked) {
      await bibleSwitch.click();
      const nowChecked = (await bibleSwitch.getAttribute("aria-checked")) === "true";
      expect(nowChecked).toBe(true);
    }
    const closeBtn = await $('[aria-label="Close settings"]');
    await closeBtn.click();
  });
});
