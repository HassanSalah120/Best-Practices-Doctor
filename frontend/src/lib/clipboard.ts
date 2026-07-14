export async function copyTextToClipboard(text: string): Promise<boolean> {
  // Prefer the async Clipboard API when available.
  try {
    if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // Fall through to the legacy path.
  }

  // Legacy fallback for WebView/older contexts.
  try {
    if (typeof document === "undefined") return false;

    const el = document.createElement("textarea");
    el.value = text;
    el.setAttribute("readonly", "true");
    el.style.position = "fixed";
    el.style.left = "-9999px";
    el.style.top = "0";
    document.body.appendChild(el);

    el.focus();
    el.select();

    // document.execCommand is deprecated but still widely supported.
    const ok = document.execCommand?.("copy") ?? false;
    document.body.removeChild(el);
    return ok;
  } catch {
    return false;
  }
}

