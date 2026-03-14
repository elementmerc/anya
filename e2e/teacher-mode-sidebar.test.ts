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
    const btn = await $('[aria-label="Open settings"]');
    await btn.click();
    const modal = await $('[role="dialog"][aria-label="Settings"]');
    await modal.waitForDisplayed({ timeout: 3000 });
    return modal;
  }

  async function closeSettings() {
    const closeBtn = await $('[aria-label="Close settings"]');
    await closeBtn.click();
  }

  async function enableTeacherMode() {
    await openSettings();
    const switches = await $$('[role="switch"]');
    // Teacher Mode is the first switch in the Learning section
    const teacherSwitch = switches[0];
    const isOn = (await teacherSwitch.getAttribute("aria-checked")) === "true";
    if (!isOn) {
      await teacherSwitch.click();
    }
    await closeSettings();
  }

  async function disableTeacherMode() {
    await openSettings();
    const switches = await $$('[role="switch"]');
    const teacherSwitch = switches[0];
    const isOn = (await teacherSwitch.getAttribute("aria-checked")) === "true";
    if (isOn) {
      await teacherSwitch.click();
    }
    await closeSettings();
  }

  it("Teacher Mode toggle changes aria-checked in Settings modal", async () => {
    await openSettings();
    const switches = await $$('[role="switch"]');
    const teacherSwitch = switches[0];
    const before = await teacherSwitch.getAttribute("aria-checked");
    await teacherSwitch.click();
    const after = await teacherSwitch.getAttribute("aria-checked");
    expect(after).not.toBe(before);
    // Restore
    await teacherSwitch.click();
    await closeSettings();
  });

  it("sidebar panel becomes visible when Teacher Mode is enabled", async () => {
    await enableTeacherMode();
    await browser.pause(400); // allow transition
    // The sidebar has a heading with text "Teacher Mode"
    const headings = await $$("span");
    const teacherHeading = await Promise.all(
      headings.map(async (el) => ({ el, text: await el.getText() }))
    ).then((items) => items.find(({ text }) => text === "Teacher Mode"));
    expect(teacherHeading).toBeDefined();
  });

  it("sidebar shows empty-state prompt when no item is focused", async () => {
    // Ensure Teacher Mode is on
    await enableTeacherMode();
    const body = await $("body");
    const text = await body.getText();
    expect(text).toContain("Click or hover any flagged item");
  });

  it("X button on sidebar disables Teacher Mode", async () => {
    await enableTeacherMode();
    await browser.pause(400);
    const disableBtn = await $('[title="Disable Teacher Mode"]');
    await disableBtn.waitForDisplayed({ timeout: 3000 });
    await disableBtn.click();
    await browser.pause(400);
    // After clicking X, verify teacher mode is off by checking Settings
    await openSettings();
    const switches = await $$('[role="switch"]');
    const isOn = (await switches[0].getAttribute("aria-checked")) === "true";
    expect(isOn).toBe(false);
    await closeSettings();
  });

  after(async () => {
    // Leave Teacher Mode off
    await disableTeacherMode();
  });
});
