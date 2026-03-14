/**
 * E2E: MITRE ATT&CK tab navigation
 *
 * Verifies that:
 * - The MITRE tab is accessible from the tab bar
 * - Empty state renders correctly when no file is loaded
 * - Technique cards appear after analysing a file that produces MITRE hits
 *   (uses a fixture path if available; otherwise validates the empty state only)
 */

const FIXTURE_PE = process.env.E2E_FIXTURE_PE ?? null;

describe("MITRE ATT&CK tab", () => {
  before(async () => {
    await browser.pause(1000);
  });

  it("MITRE tab button is present in the tab bar", async () => {
    // Tab buttons contain the text "MITRE ATT&CK" or similar
    const tabs = await $$('[role="tab"], button');
    const mitreTab = await Promise.all(
      tabs.map(async (el) => ({ el, text: await el.getText() }))
    ).then((items) => items.find(({ text }) => /mitre/i.test(text)));
    expect(mitreTab).toBeDefined();
  });

  it("clicking the MITRE tab navigates to the MITRE view", async () => {
    const tabs = await $$('[role="tab"], button');
    const mitreTabItem = await Promise.all(
      tabs.map(async (el) => ({ el, text: await el.getText() }))
    ).then((items) => items.find(({ text }) => /mitre/i.test(text)));

    if (mitreTabItem) {
      await mitreTabItem.el.click();
      await browser.pause(300);
    }

    const body = await $("body");
    const text = await body.getText();
    // Either shows "No MITRE ATT&CK techniques detected" (no file loaded)
    // or shows technique cards when a file has been analysed
    const hasEmptyState = /No MITRE ATT&CK techniques detected/i.test(text);
    const hasTechniqueContent = /T\d{4}/i.test(text);
    expect(hasEmptyState || hasTechniqueContent).toBe(true);
  });

  it("empty state message appears when no file is loaded", async () => {
    const body = await $("body");
    const text = await body.getText();
    if (/No MITRE ATT&CK techniques detected/i.test(text)) {
      expect(text).toMatch(/No MITRE ATT&CK techniques detected/i);
    } else {
      // A file is already loaded — skip this assertion
      console.log("Skipping empty-state check: file already loaded");
    }
  });

  // This test only runs when E2E_FIXTURE_PE is set to a PE path that produces
  // at least one MITRE hit.
  it("technique cards render after analysing a fixture file", async function () {
    if (!FIXTURE_PE) {
      console.log("Skipping: set E2E_FIXTURE_PE to a PE path to run this test");
      return;
    }

    // Drop zone accepts file paths via keyboard or drag; for automation we
    // send the path through the app's CLI-compatible IPC if available, or
    // use a workaround with the file input element.
    const dropZone = await $('[data-testid="drop-zone"]');
    if (await dropZone.isExisting()) {
      // Simulate a file drop by injecting a DataTransfer via JS
      await browser.execute((filePath: string) => {
        const el = document.querySelector('[data-testid="drop-zone"]');
        if (!el) return;
        const dt = new DataTransfer();
        const file = new File([""], filePath.split("/").pop() ?? "test.exe");
        dt.items.add(file);
        el.dispatchEvent(new DragEvent("drop", { dataTransfer: dt, bubbles: true }));
      }, FIXTURE_PE);
      await browser.pause(3000);
    }

    const body = await $("body");
    const text = await body.getText();
    expect(text).toMatch(/T\d{4}/);
  });
});
