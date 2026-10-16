(() => {
  const panel = document.querySelector('.payload-panel');
  if (!panel) return;
  panel.addEventListener('click', async (event) => {
    const button = event.target.closest('[data-copy-payload]');
    if (!button) return;
    const command = document.getElementById(button.dataset.copyPayload);
    const status = panel.querySelector('.payload-copy-status');
    try {
      await navigator.clipboard.writeText(command.value);
      status.textContent = '명령을 복사했습니다.';
      button.textContent = '복사됨';
      setTimeout(() => { button.textContent = '복사'; }, 1500);
    } catch {
      command.focus();
      command.select();
      status.textContent = '명령을 선택했습니다. Ctrl+C 또는 ⌘C로 복사하세요.';
    }
  });
})();
