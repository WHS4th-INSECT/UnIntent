(() => {
  const q = (selector) => document.querySelector(selector);
  const runtimeStatus = q("#runtime-status");
  const terminalHost = q("#xterm-terminal");
  if (!runtimeStatus || !terminalHost) return;

  const state = {
    runtime: null,
    avdName: null,
    serial: null,
    pointer: null,
    lastPointerGestureAt: 0,
    terminalId: null,
    terminalAlive: false,
    outputBusy: false,
  };

  async function api(url, options = {}) {
    const response = await fetch(url, {
      ...options,
      headers: options.body
        ? { "Content-Type": "application/json", ...(options.headers || {}) }
        : options.headers,
    });
    const payload = await response.json();
    if (!response.ok) {
      const error = new Error(payload.error || String(response.status) + " " + response.statusText);
      error.status = response.status;
      throw error;
    }
    return payload;
  }

  function escapeText(value) {
    return String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;");
  }

  function escapeAttribute(value) {
    return escapeText(value).replaceAll('"', "&quot;");
  }

  function setRuntimeMessage(message, error = false) {
    runtimeStatus.textContent = message;
    runtimeStatus.classList.toggle("runtime-error", error);
  }

  function renderRuntime(runtime) {
    state.runtime = runtime;
    const avdSelect = q("#avd-select");
    const avdKey = runtime.avds.join("\n");
    if (avdSelect.dataset.avdKey !== avdKey) {
      avdSelect.innerHTML = runtime.avds.length
        ? runtime.avds.map((name) => '<option value="' + escapeAttribute(name) + '">' + escapeText(name) + "</option>").join("")
        : '<option value="">등록된 AVD 없음</option>';
      avdSelect.dataset.avdKey = avdKey;
    }
    const onlineDevices = runtime.devices.filter((device) => device.state === "device");
    if (!state.avdName || !runtime.avds.includes(state.avdName)) {
      const activeEmulator = onlineDevices.find((device) => device.avd_name);
      state.avdName = activeEmulator?.avd_name || runtime.avds[0] || null;
    }
    avdSelect.value = state.avdName || "";

    const selected = onlineDevices.find((device) => device.avd_name === state.avdName);
    state.serial = selected?.serial || null;
    q("#avd-start").disabled = !runtime.emulator_path || !runtime.avds.length || Boolean(selected);
    q("#avd-start").textContent = selected ? "● Running" : "▶ Start";
    q("#avd-stop").disabled = !state.serial?.startsWith("emulator-");
    q("#device-empty").hidden = Boolean(selected);
    if (!selected) {
      q("#device-screen").hidden = true;
      q("#device-screen").removeAttribute("src");
      q("#device-empty-title").textContent = state.avdName
        ? state.avdName + "은(는) 실행 중이 아닙니다"
        : "연결된 에뮬레이터 없음";
      q("#device-empty-message").textContent = state.avdName
        ? "Start를 눌러 선택한 AVD를 실행하세요."
        : "AVD를 생성하거나 Android SDK 설정을 확인하세요.";
    }
    setRuntimeMessage(
      runtime.available
        ? runtime.platform.toUpperCase() + " · " + onlineDevices.length + " device" + (onlineDevices.length === 1 ? "" : "s")
        : "Android SDK 미연결",
      !runtime.available,
    );
  }

  async function refreshRuntime() {
    try {
      renderRuntime(await api("/api/local/runtime"));
      refreshScreen();
    } catch (error) {
      setRuntimeMessage(error.message, true);
    }
  }

  const videoStream = new DeviceVideoStream(
    q("#device-screen"),
    () => { q("#device-empty").hidden = true; },
  );

  function refreshScreen() {
    videoStream.select(location.hash === "#analyze" && !document.hidden ? state.serial : null);
  }

  async function startAvd() {
    const avdName = q("#avd-select").value;
    if (!avdName) return;
    q("#avd-start").disabled = true;
    setRuntimeMessage(avdName + " 시작 중");
    try {
      await api("/api/local/emulator/start", {
        method: "POST",
        body: JSON.stringify({ avd_name: avdName }),
      });
      window.setTimeout(refreshRuntime, 1800);
    } catch (error) {
      setRuntimeMessage(error.message, true);
      q("#avd-start").disabled = false;
    }
  }

  async function stopAvd() {
    if (!state.serial) return;
    try {
      await api("/api/local/emulator/stop", {
        method: "POST",
        body: JSON.stringify({ serial: state.serial }),
      });
      state.serial = null;
      await refreshRuntime();
    } catch (error) {
      setRuntimeMessage(error.message, true);
    }
  }

  if (!window.Terminal) {
    terminalHost.textContent = "xterm.js를 불러오지 못했습니다.";
    return;
  }

  const terminal = new window.Terminal({
    allowProposedApi: false,
    convertEol: false,
    cursorBlink: true,
    cursorStyle: "block",
    disableStdin: true,
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
    fontSize: 12,
    lineHeight: 1.25,
    scrollback: 5000,
    theme: {
      background: "#0a0d12",
      foreground: "#d8dde7",
      cursor: "#a77cff",
      cursorAccent: "#0a0d12",
      selectionBackground: "#7048ce66",
      black: "#0a0d12",
      brightBlack: "#687080",
      red: "#ff6b78",
      green: "#45d19a",
      yellow: "#f5c451",
      blue: "#75a7ff",
      magenta: "#b890ff",
      cyan: "#58c8d8",
      white: "#d8dde7",
      brightWhite: "#ffffff",
    },
  });
  const fitAddon = new FitAddon.FitAddon();
  terminal.loadAddon(fitAddon);
  terminal.open(terminalHost);
  terminal.write("로컬 셸을 시작하려면 Start shell을 누르세요.\r\n");

  let resizeTimer = null;
  let pendingInput = "";
  let inputTimer = null;
  let inputChain = Promise.resolve();

  function fitTerminal() {
    const width = terminalHost.clientWidth;
    const height = terminalHost.clientHeight;
    if (width < 40 || height < 40) return;
    const previousCols = terminal.cols;
    const previousRows = terminal.rows;
    fitAddon.fit();
    if (previousCols === terminal.cols && previousRows === terminal.rows) return;
    window.clearTimeout(resizeTimer);
    resizeTimer = window.setTimeout(async () => {
      if (!state.terminalId || !state.terminalAlive) return;
      try {
        await api("/api/local/terminal/sessions/" + state.terminalId + "/resize", {
          method: "POST",
          body: JSON.stringify({ rows: terminal.rows, cols: terminal.cols }),
        });
      } catch (error) {
        q("#terminal-shell-label").textContent = error.message;
      }
    }, 80);
  }

  async function startTerminal() {
    if (state.terminalId) {
      await fetch("/api/local/terminal/sessions/" + state.terminalId, { method: "DELETE" });
    }
    fitTerminal();
    q("#terminal-start").disabled = true;
    try {
      const session = await api("/api/local/terminal/sessions", {
        method: "POST",
        body: JSON.stringify({ rows: terminal.rows, cols: terminal.cols }),
      });
      state.terminalId = session.session_id;
      state.terminalAlive = true;
      terminal.reset();
      terminal.options.disableStdin = false;
      q("#terminal-shell-label").textContent = session.shell + " · " + session.cwd;
      q("#terminal-interrupt").disabled = false;
      q("#terminal-start").textContent = "Restart";
      terminal.focus();
      await pollTerminal();
    } catch (error) {
      terminal.writeln("\r\n터미널을 시작하지 못했습니다: " + error.message);
    } finally {
      q("#terminal-start").disabled = false;
    }
  }

  async function sendTerminalInput(data) {
    if (!state.terminalId || !state.terminalAlive) return;
    await api("/api/local/terminal/sessions/" + state.terminalId + "/input", {
      method: "POST",
      body: JSON.stringify({ data }),
    });
  }

  function queueTerminalInput(data) {
    if (!state.terminalId || !state.terminalAlive) return;
    pendingInput += data;
    if (inputTimer) return;
    inputTimer = window.setTimeout(() => {
      const chunk = pendingInput;
      pendingInput = "";
      inputTimer = null;
      inputChain = inputChain
        .then(() => sendTerminalInput(chunk))
        .then(() => window.setTimeout(pollTerminal, 15))
        .catch((error) => {
          q("#terminal-shell-label").textContent = error.message;
        });
    }, 8);
  }

  async function pollTerminal() {
    if (!state.terminalId || !state.terminalAlive || state.outputBusy) return;
    state.outputBusy = true;
    try {
      const output = await api("/api/local/terminal/sessions/" + state.terminalId + "/output");
      if (output.data) terminal.write(output.data);
      if (!output.alive) {
        state.terminalAlive = false;
        terminal.options.disableStdin = true;
        q("#terminal-interrupt").disabled = true;
        q("#terminal-start").textContent = "Start shell";
      }
    } catch (error) {
      q("#terminal-shell-label").textContent = error.message;
      if (error.status === 404) {
        state.terminalId = null;
        state.terminalAlive = false;
        terminal.options.disableStdin = true;
        q("#terminal-interrupt").disabled = true;
        q("#terminal-start").textContent = "Start shell";
      }
    } finally {
      state.outputBusy = false;
    }
  }

  q("#avd-select").addEventListener("change", (event) => {
    state.avdName = event.currentTarget.value || null;
    state.serial = null;
    if (state.runtime) renderRuntime(state.runtime);
    refreshScreen();
  });
  q("#avd-start").addEventListener("click", startAvd);
  q("#avd-stop").addEventListener("click", stopAvd);
  q("#terminal-start").addEventListener("click", startTerminal);
  q("#terminal-console").addEventListener("click", () => {
    if (state.terminalAlive) terminal.focus();
  });
  q("#terminal-clear").addEventListener("click", () => {
    terminal.clear();
    terminal.focus();
  });
  q("#terminal-interrupt").addEventListener("click", () => {
    queueTerminalInput("\x03");
    terminal.focus();
  });
  terminal.onData(queueTerminalInput);

  const resizeObserver = new ResizeObserver(() => fitTerminal());
  resizeObserver.observe(terminalHost);
  window.addEventListener("resize", fitTerminal);
  document.fonts.ready.then(fitTerminal);
  document.fonts.addEventListener("loadingdone", fitTerminal);
  window.addEventListener("hashchange", () => window.setTimeout(fitTerminal, 0));

  window.addEventListener("beforeunload", () => {
    videoStream.stop();
    if (state.terminalId) {
      fetch("/api/local/terminal/sessions/" + state.terminalId, {
        method: "DELETE",
        keepalive: true,
      });
    }
  });

  fitTerminal();
  refreshRuntime();
  window.setInterval(() => {
    if (location.hash === "#analyze") refreshRuntime();
  }, 5000);
  window.addEventListener("hashchange", refreshScreen);
  window.addEventListener("dashboard:pagechange", () => { refreshScreen(); fitTerminal(); });
  document.addEventListener("visibilitychange", refreshScreen);
  window.addEventListener("pagehide", () => videoStream.stop());
  window.addEventListener("pageshow", refreshScreen);
  window.setInterval(pollTerminal, 80);
})();
