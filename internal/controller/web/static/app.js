// SPDX-License-Identifier: AGPL-3.0-only
// Confirmation for dangerous actions and copy-to-clipboard buttons.
document.addEventListener("submit", (e) => {
  const msg = e.target.dataset.confirm;
  if (msg && !confirm(msg)) e.preventDefault();
});
document.addEventListener("click", async (e) => {
  const id = e.target.dataset && e.target.dataset.copy;
  if (!id) return;
  const text = document.getElementById(id).textContent;
  try {
    await navigator.clipboard.writeText(text);
    e.target.textContent = "Скопировано";
  } catch {
    const r = document.createRange();
    r.selectNodeContents(document.getElementById(id));
    getSelection().removeAllRanges();
    getSelection().addRange(r);
  }
});
