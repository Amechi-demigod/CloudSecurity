// /scanner page: copy buttons for the scanner's identifiers.
document.querySelectorAll(".copy").forEach((b) => {
  b.addEventListener("click", () => {
    if (!navigator.clipboard) return;
    navigator.clipboard.writeText(b.dataset.t).then(() => {
      b.textContent = "Copied";
      setTimeout(() => { b.textContent = "Copy"; }, 1200);
    }, () => {});
  });
});
