/* scrcpy 3.3.4 Annex-B H.264 -> WebCodecs. No screenshot polling. */
class DeviceVideoStream {
  constructor(canvas, onFrame) {
    this.canvas = canvas;
    this.context = canvas.getContext("2d", { alpha: false });
    this.onFrame = onFrame;
    this.serial = null;
    this.retry = 0;
    this.generation = 0;
    this.bindInput();
  }

  select(serial) {
    if (serial === this.serial) return;
    this.stop();
    this.serial = serial;
    this.retry = 0;
    if (serial) this.connect();
  }

  stop() {
    this.generation++;
    clearTimeout(this.timer);
    clearTimeout(this.watchdog);
    this.pointer = null;
    if (this.ws) {
      this.ws.onclose = null;
      this.ws.close();
      this.ws = null;
    }
    if (this.decoder && this.decoder.state !== "closed") this.decoder.close();
    this.decoder = null;
    this.serial = null;
    this.canvas.hidden = true;
  }

  connect() {
    if (!this.serial) return;
    if (!("VideoDecoder" in window) || !window.isSecureContext) {
      console.error("이 브라우저에서 영상 디코딩을 지원하지 않습니다. localhost의 최신 Chrome을 사용하세요.");
      return;
    }
    const generation = ++this.generation;
    const current = () => this.generation === generation;
    let config = null;
    let waitingForKey = true;
    let count = 0;
    let displayed = false;
    const ws = new WebSocket(`${location.protocol === "https:" ? "wss:" : "ws:"}//${location.host}/api/local/devices/${encodeURIComponent(this.serial)}/stream`);
    this.ws = ws;
    ws.binaryType = "arraybuffer";
    const fail = (error) => {
      if (!current()) return;
      console.warn("Device stream:", error.message || String(error));
      ws.close();
    };
    const decoder = new VideoDecoder({
      output: (frame) => {
        try {
          if (!current()) return;
          if (this.canvas.width !== frame.displayWidth || this.canvas.height !== frame.displayHeight) {
            this.canvas.width = frame.displayWidth;
            this.canvas.height = frame.displayHeight;
            this.canvas.style.setProperty("--device-aspect", frame.displayWidth / frame.displayHeight);
          }
          this.context.drawImage(frame, 0, 0);
          this.canvas.hidden = false;
          if (!displayed) {
            displayed = true;
            clearTimeout(this.watchdog);
            this.retry = 0;
            this.onFrame();
          }
        } finally { frame.close(); }
      },
      error: fail,
    });
    this.decoder = decoder;
    this.watchdog = setTimeout(() => fail(new Error("영상 응답 지연 · 다시 연결합니다")), 15000);
    ws.onmessage = (event) => {
      if (!current()) return;
      try {
        if (typeof event.data === "string") {
          const message = JSON.parse(event.data);
          if (message.type === "error") throw new Error(message.message);
          return;
        }
        const header = new DataView(event.data);
        if (header.byteLength < 12 || header.getUint32(8) !== header.byteLength - 12) throw new Error("잘못된 영상 패킷");
        const flags = header.getBigUint64(0);
        const isConfig = Boolean(flags & (1n << 63n));
        const isKey = Boolean(flags & (1n << 62n));
        let data = new Uint8Array(event.data, 12);
        if (isConfig) {
          config = data.slice();
          let codec = null;
          for (let i = 0; i + 6 < data.length; i++) {
            if (data[i] === 0 && data[i + 1] === 0 && data[i + 2] === 1 && (data[i + 3] & 31) === 7) {
              codec = "avc1." + Array.from(data.slice(i + 4, i + 7), (x) => x.toString(16).padStart(2, "0")).join("");
              break;
            }
          }
          if (!codec) throw new Error("H.264 SPS 설정을 읽을 수 없습니다");
          decoder.reset();
          decoder.configure({ codec, optimizeForLatency: true, hardwareAcceleration: "no-preference" });
          waitingForKey = true;
        } else if (decoder.state === "configured" && (!waitingForKey || isKey)) {
          if (decoder.decodeQueueSize > 6) throw new Error("영상 처리 지연 · 다시 연결합니다");
          if (isKey && config) {
            const joined = new Uint8Array(config.length + data.length);
            joined.set(config);
            joined.set(data, config.length);
            data = joined;
          }
          decoder.decode(new EncodedVideoChunk({
            type: isKey ? "key" : "delta",
            timestamp: Number(flags & ((1n << 62n) - 1n)),
            data,
          }));
          waitingForKey = false;
        }
        this.send({ type: "ack", count: ++count });
      } catch (error) { fail(error); }
    };
    ws.onclose = () => {
      if (!current()) return;
      clearTimeout(this.watchdog);
      this.pointer = null;
      this.canvas.hidden = true;
      if (decoder.state !== "closed") decoder.close();
      this.timer = setTimeout(() => this.connect(), Math.min(10000, 500 * 2 ** this.retry++));
    };
  }

  send(message) {
    if (this.ws?.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify(message));
  }

  point(event) {
    const bounds = this.canvas.getBoundingClientRect();
    return {
      x: Math.max(0, Math.min(this.canvas.width - 1, Math.round((event.clientX - bounds.left) * this.canvas.width / bounds.width))),
      y: Math.max(0, Math.min(this.canvas.height - 1, Math.round((event.clientY - bounds.top) * this.canvas.height / bounds.height))),
      width: this.canvas.width, height: this.canvas.height,
    };
  }

  bindInput() {
    const canvas = this.canvas;
    canvas.addEventListener("pointerdown", (event) => {
      if ((this.pointer !== null && this.pointer !== undefined) || canvas.hidden || event.button !== 0) return;
      event.preventDefault();
      this.pointer = event.pointerId;
      canvas.setPointerCapture(event.pointerId);
      canvas.focus();
      this.send({ type: "touch", action: 0, ...this.point(event) });
    });
    canvas.addEventListener("pointermove", (event) => {
      if (this.pointer !== event.pointerId) return;
      event.preventDefault();
      this.send({ type: "touch", action: 2, ...this.point(event) });
    });
    const release = (event, action) => {
      if (this.pointer !== event.pointerId) return;
      this.send({ type: "touch", action, ...this.point(event) });
      this.pointer = null;
      if (canvas.hasPointerCapture(event.pointerId)) canvas.releasePointerCapture(event.pointerId);
    };
    canvas.addEventListener("pointerup", (event) => release(event, 1));
    canvas.addEventListener("pointercancel", (event) => release(event, 3));
    canvas.addEventListener("lostpointercapture", (event) => release(event, 3));
    canvas.addEventListener("contextmenu", (event) => event.preventDefault());
    canvas.addEventListener("wheel", (event) => {
      event.preventDefault();
      this.send({ type: "scroll", ...this.point(event), horizontal: -event.deltaX / 100, vertical: -event.deltaY / 100 });
    }, { passive: false });
    canvas.addEventListener("keydown", (event) => {
      if (event.ctrlKey || event.metaKey || event.altKey || event.isComposing) return;
      const keys = { ArrowUp: 19, ArrowDown: 20, ArrowLeft: 21, ArrowRight: 22, Enter: 66, Backspace: 67, Escape: 4, Home: 3, Tab: 61, Delete: 112 };
      if (keys[event.key] !== undefined) {
        event.preventDefault();
        this.send({ type: "key", keycode: keys[event.key] });
      } else if (event.key.length === 1) {
        event.preventDefault();
        this.send({ type: "text", text: event.key });
      }
    });
  }
}
