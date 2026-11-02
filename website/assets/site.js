// Travound Security website: "Request a demo" form. Sends the form as JSON to
// POST /api/contact and shows the result in place (no page reload). Without
// JavaScript the form posts normally and the server redirects to
// /#contact-sent or /#contact-error (shown by CSS :target).
(function () {
  "use strict";
  var form = document.getElementById("demo-form");
  if (!form || !window.fetch || !window.JSON) return;
  var button = form.querySelector('button[type="submit"]');
  var status = form.querySelector("[data-form-status]");
  var label = button.textContent;
  var FIELDS = ["name", "email", "company", "interest", "message", "website"];

  function show(kind, text) {
    status.className = "form-msg " + kind;
    status.textContent = text;
    status.hidden = false;
  }

  function invalidFields() {
    var bad = [];
    ["name", "email", "company"].forEach(function (n) {
      var el = form.elements[n];
      var ok = el.value.trim() !== "" && el.checkValidity();
      el.setAttribute("aria-invalid", ok ? "false" : "true");
      if (!ok) bad.push(el);
    });
    return bad;
  }

  form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    if (button.disabled) return;
    var bad = invalidFields();
    if (bad.length) {
      show("err", "Please fill in your name, a valid work email and your company.");
      bad[0].focus();
      return;
    }
    var body = {};
    FIELDS.forEach(function (n) { body[n] = form.elements[n] ? form.elements[n].value : ""; });
    button.disabled = true;
    button.textContent = "Sending…";
    status.hidden = true;
    fetch(form.getAttribute("action"), {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      credentials: "omit",
      body: JSON.stringify(body)
    }).then(function (res) {
      if (res.ok) {
        form.reset();
        show("ok", "Thanks, your request has been sent. We'll be in touch shortly.");
      } else if (res.status === 429) {
        show("err", "Too many requests from your network. Please try again later.");
      } else if (res.status === 400 || res.status === 422) {
        show("err", "Please check the form: your name, a valid work email and your company are required.");
      } else {
        show("err", "Sorry, your request could not be sent. Please try again in a few minutes.");
      }
    }).catch(function () {
      show("err", "Sorry, your request could not be sent. Please check your connection and try again.");
    }).then(function () {
      button.disabled = false;
      button.textContent = label;
    });
  });
})();
