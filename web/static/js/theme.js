(() => {
  const storageKey = "intent-flow-theme";
  const root = document.documentElement;
  const themeButtons = [...document.querySelectorAll("[data-theme-choice]")];
  const systemTheme = window.matchMedia("(prefers-color-scheme: dark)");

  function activeTheme() {
    return root.dataset.theme === "dark" ? "dark" : "light";
  }

  function renderTheme(theme, persist = false) {
    root.dataset.theme = theme;
    root.style.colorScheme = theme;
    document.querySelector('meta[name="theme-color"]')?.setAttribute(
      "content",
      theme === "dark" ? "#111318" : "#f7f7f5",
    );
    themeButtons.forEach((button) => {
      const selected = button.dataset.themeChoice === theme;
      button.setAttribute("aria-pressed", String(selected));
    });
    if (persist) localStorage.setItem(storageKey, theme);
    window.dispatchEvent(new Event("resize"));
  }

  themeButtons.forEach((button) => {
    button.addEventListener("click", () => renderTheme(button.dataset.themeChoice, true));
  });

  systemTheme.addEventListener("change", (event) => {
    if (!localStorage.getItem(storageKey)) renderTheme(event.matches ? "dark" : "light");
  });

  document.querySelector("#sidebar-search-button")?.addEventListener("click", () => {
    document.querySelector('.page-nav[data-page="static"]')?.click();
    window.setTimeout(() => document.querySelector("#graph-search")?.focus(), 0);
  });

  document.addEventListener("keydown", (event) => {
    if (event.key !== "/" || event.metaKey || event.ctrlKey || event.altKey) return;
    const target = event.target;
    if (target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement || target instanceof HTMLSelectElement) return;
    event.preventDefault();
    document.querySelector("#sidebar-search-button")?.click();
  });

  renderTheme(activeTheme());
})();
