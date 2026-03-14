/**
 * E2E: Teacher Mode sidebar
 *
 * Verifies that:
 * - Teacher Mode can be enabled via Settings
 * - The sidebar panel appears when Teacher Mode is on
 * - The sidebar shows the empty-state prompt when no item is focused
 * - The X button closes the sidebar
 */
describe("Teacher Mode sidebar", () => {
  before(async () => {
    await browser.pause(1000);
  });

  async function openSettings() {
    const btn = await $('[data-testid="settings-button"]');
    await btn.click();
    const modal = await $('[role="dialog"][aria-label="Settings"]');
    await modal.waitForDisplayed({ timeout: 3000 });
    return modal;
  }

  async function closeSettings() {
    const closeBtn = await $('[aria-label="Close settings"]');
    await closeBtn.click();
  }

  async function getTeacherToggle() {
    return $('[data-testid="teacher-mode-toggle"]');
  }

  async function enableTeacherMode() {
    await openSettings();
    const toggle = await getTeacherToggle();
    const isOn = (await toggle.getAttribute("aria-checked")) === "true";
    if (!isOn) await toggle.click();
    await closeSettings();
    await browser.pause(350); // allow sidebar transition
  }

  async function disableTeacherMode() {
    await openSettings();
    const toggle = await getTeacherToggle();
    const isOn = (await toggle.getAttribute("aria-checked")) === "true";
    if (isOn) await toggle.click();
    await closeSettings();
    await browser.pause(350);
  }

  it("Settings modal opens when the settings button is clicked", async () => {
    const panel = await (await openSettings()).$('[data-testid="settings-panel"]');
    await expect(panel).toBeDisplayed();
    await closeSettings();
  });

  it("Teacher Mode toggle changes aria-checked", async () => {
    await openSettings();
    const toggle = await getTeacherToggle();
    const before = await toggle.getAttribute("aria-checked");
    await toggle.click();
    const after = await toggle.getAttribute("aria-checked");
    expect(after).not.toBe(before);
    // Restore original state
    await toggle.click();
    await closeSettings();
  });

  it("sidebar panel becomes visible when Teacher Mode is enabled", async () => {
    await enableTeacherMode();
    const sidebar = await $('[data-testid="teacher-sidebar"]');
    await expect(sidebar).toBeDisplayed();
    // The sidebar's inner content should be wider than 0 (transition complete)
    const width = await browser.execute(
      (el: Element) => (el as HTMLElement).getBoundingClientRect().width,
      sidebar
    );
    expect(width).toBeGreaterThan(0);
  });

  it("sidebar shows the empty-state prompt when no item is focused", async () => {
    await enableTeacherMode();
    const prompt = await $('[data-testid="sidebar-default-prompt"]');
    await expect(prompt).toBeDisplayed();
    const text = await prompt.getText();
    expect(text).toContain("Click or hover any flagged item");
  });

  it("X button on the sidebar disables Teacher Mode", async () => {
    await enableTeacherMode();
    const disableBtn = await $('[title="Disable Teacher Mode"]');
    await disableBtn.waitForDisplayed({ timeout: 3000 });
    await disableBtn.click();
    await browser.pause(350);

    // Sidebar width collapses to 0
    const sidebar = await $('[data-testid="teacher-sidebar"]');
    const width = await browser.execute(
      (el: Element) => (el as HTMLElement).getBoundingClientRect().width,
      sidebar
    );
    expect(width).toBe(0);
  });

  after(async () => {
    // Leave Teacher Mode off to avoid polluting other tests
    try {
      await disableTeacherMode();
    } catch {
      // ignore if settings can't be opened (e.g. modal already closed)
    }
  });
});
