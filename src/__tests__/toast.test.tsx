import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, act } from "@testing-library/react";
import { ToastProvider, useToast } from "../../ui/components/Toast";

// Helper component that exposes the toast function for testing
function ToastTrigger({ message, type }: { message: string; type: "success" | "error" | "warning" | "info" }) {
  const { toast } = useToast();
  return <button onClick={() => toast(message, type)}>Trigger</button>;
}

describe("Toast", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  it("renders a success toast", async () => {
    render(
      <ToastProvider>
        <ToastTrigger message="Saved!" type="success" />
      </ToastProvider>
    );
    await act(async () => {
      screen.getByText("Trigger").click();
    });
    expect(screen.getByText("Saved!")).toBeDefined();
  });

  it("renders an error toast", async () => {
    render(
      <ToastProvider>
        <ToastTrigger message="Something broke" type="error" />
      </ToastProvider>
    );
    await act(async () => {
      screen.getByText("Trigger").click();
    });
    expect(screen.getByText("Something broke")).toBeDefined();
  });

  it("auto-dismisses after timeout", async () => {
    render(
      <ToastProvider>
        <ToastTrigger message="Temporary" type="info" />
      </ToastProvider>
    );
    await act(async () => {
      screen.getByText("Trigger").click();
    });
    expect(screen.getByText("Temporary")).toBeDefined();

    // Advance past the auto-dismiss timeout (3 seconds)
    await act(async () => {
      vi.advanceTimersByTime(4000);
    });
    expect(screen.queryByText("Temporary")).toBeNull();
  });

  it("limits to 3 toasts maximum", async () => {
    function MultiTrigger() {
      const { toast } = useToast();
      return (
        <>
          <button onClick={() => toast("Toast 1", "info")}>T1</button>
          <button onClick={() => toast("Toast 2", "info")}>T2</button>
          <button onClick={() => toast("Toast 3", "info")}>T3</button>
          <button onClick={() => toast("Toast 4", "info")}>T4</button>
        </>
      );
    }
    render(
      <ToastProvider>
        <MultiTrigger />
      </ToastProvider>
    );
    await act(async () => {
      screen.getByText("T1").click();
      screen.getByText("T2").click();
      screen.getByText("T3").click();
      screen.getByText("T4").click();
    });
    // Should only show the 3 most recent
    expect(screen.queryByText("Toast 1")).toBeNull();
    expect(screen.getByText("Toast 4")).toBeDefined();
  });
});
