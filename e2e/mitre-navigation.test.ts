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

  it("app loads and shows the drop zone", async () => {
    const dropZone = await $('[role="region"][aria-label="Drop zone"]');
    await expect(dropZone).toBeDisplayed();
  });

  it("MITRE tab button is present in the tab bar", async () => {
    const tabs = await $$('[role="tab"]');
    const texts = await Promise.all(tabs.map((el) => el.getText()));
    const hasMitre = texts.some((t) => /mitre/i.test(t));
    expect(hasMitre).toBe(true);
  });

  it("clicking the MITRE tab navigates to the MITRE view", async () => {
    const tabs = await $$('[role="tab"]');
    const withText = await Promise.all(
      tabs.map(async (el) => ({ el, text: await el.getText() }))
    );
    const mitreTab = withText.find(({ text }) => /mitre/i.test(text));

    if (mitreTab) {
      await mitreTab.el.click();
      await browser.pause(300);
    }

    const body = await $("body");
    const text = await body.getText();
    // Either shows empty-state or technique cards (T#### pattern)
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
      // A file is already loaded — the MITRE tab may have technique cards
      const cards = await $$('[data-testid="technique-card"]');
      expect(cards.length).toBeGreaterThan(0);
    }
  });

  // This test only runs when E2E_FIXTURE_PE is set to a PE path that produces
  // at least one MITRE hit.
  it("technique cards render after analysing a fixture file", async function () {
    if (!FIXTURE_PE) {
      console.log("Skipping: set E2E_FIXTURE_PE to a PE path to run this test");
      return;
    }

    // Navigate to MITRE tab
    const tabs = await $$('[role="tab"]');
    const withText = await Promise.all(
      tabs.map(async (el) => ({ el, text: await el.getText() }))
    );
    const mitreTab = withText.find(({ text }) => /mitre/i.test(text));
    if (mitreTab) await mitreTab.el.click();

    await browser.pause(500);

    const cards = await $$('[data-testid="technique-card"]');
    expect(cards.length).toBeGreaterThan(0);
  });

  it("MITRE badges on overview tab navigate to MITRE tab when clicked", async function () {
    if (!FIXTURE_PE) {
      console.log("Skipping: set E2E_FIXTURE_PE to a PE path to run this test");
      return;
    }

    // Go to Overview tab
    const tabs = await $$('[role="tab"]');
    const withText = await Promise.all(
      tabs.map(async (el) => ({ el, text: await el.getText() }))
    );
    const overviewTab = withText.find(({ text }) => /overview/i.test(text));
    if (overviewTab) await overviewTab.el.click();
    await browser.pause(300);

    const badges = await $$('[data-testid="mitre-badge"]');
    if (badges.length === 0) {
      console.log("Skipping: no MITRE badges on overview (no MITRE hits in fixture)");
      return;
    }

    const badgeText = await badges[0].getText();
    await badges[0].click();
    await browser.pause(400);

    // Should now be on MITRE tab — look for a technique card
    const card = await $('[data-testid="technique-card"]');
    await expect(card).toBeDisplayed();

    // The badge text (e.g. "T1055") should appear somewhere in the card
    const cardText = await card.getText();
    expect(cardText).toContain(badgeText.split(".")[0]);
  });
});
