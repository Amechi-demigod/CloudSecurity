// Sentrigis website: header menus. The page works without JavaScript (menus are
// lists of links that open on hover / focus via CSS); this adds click / Enter,
// Escape, outside click, aria-expanded and the phone menu (<= 900px).
(function () {
  "use strict";
  var root = document.documentElement;
  root.classList.add("js");
  var nav = document.querySelector("nav.top");
  if (!nav) return;
  var toggle = nav.querySelector(".navtoggle");
  var menu = nav.querySelector(".menu");
  var panels = Array.prototype.slice.call(nav.querySelectorAll("li.has-panel"));
  var phone = window.matchMedia("(max-width: 900px)");
  var timer = null;

  function trigger(li) { return li.querySelector(".trig"); }
  function setOpen(li, open) {
    li.classList.toggle("open", open);
    trigger(li).setAttribute("aria-expanded", open ? "true" : "false");
  }
  function closeAll(except) {
    panels.forEach(function (li) { if (li !== except && li.classList.contains("open")) setOpen(li, false); });
  }
  function hoverCapable() { return !phone.matches; }

  panels.forEach(function (li) {
    var t = trigger(li);
    t.addEventListener("click", function () {
      if (phone.matches) return;
      var open = !li.classList.contains("open");
      closeAll(li);
      setOpen(li, open);
    });
    li.addEventListener("mouseenter", function () {
      if (!hoverCapable()) return;
      clearTimeout(timer);
      closeAll(li);
      setOpen(li, true);
    });
    li.addEventListener("mouseleave", function () {
      if (!hoverCapable()) return;
      timer = setTimeout(function () { setOpen(li, false); }, 150);
    });
  });

  // Platform: the category list on the left drives the pane on the right.
  var cats = Array.prototype.slice.call(nav.querySelectorAll(".cat"));
  function activate(cat, only) {
    cats.forEach(function (c) {
      var on = c === cat ? (only || !c.classList.contains("active")) : (only ? false : c.classList.contains("active"));
      c.classList.toggle("active", on);
      c.querySelector(".cat-btn").setAttribute("aria-expanded", on ? "true" : "false");
    });
  }
  cats.forEach(function (cat) {
    var b = cat.querySelector(".cat-btn");
    cat.addEventListener("mouseenter", function () { if (hoverCapable()) activate(cat, true); });
    b.addEventListener("focus", function () { if (hoverCapable()) activate(cat, true); });
    b.addEventListener("click", function () {
      if (hoverCapable()) activate(cat, true);
      else if (cat.classList.contains("active")) activate(null, true);
      else activate(cat, true);
    });
  });

  function setMenu(open) {
    menu.classList.toggle("open", open);
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
  }
  toggle.addEventListener("click", function () { setMenu(!menu.classList.contains("open")); });

  // On a phone the lists are always visible (no hover panels): keep them out of the tab order as buttons.
  function sync() {
    panels.forEach(function (li) {
      li.classList.remove("open");
      var t = trigger(li);
      if (phone.matches) { t.removeAttribute("aria-expanded"); t.tabIndex = -1; }
      else { t.setAttribute("aria-expanded", "false"); t.removeAttribute("tabindex"); }
    });
    if (!phone.matches) setMenu(false);
  }
  if (phone.addEventListener) phone.addEventListener("change", sync); else phone.addListener(sync);
  sync();

  document.addEventListener("keydown", function (ev) {
    if (ev.key !== "Escape") return;
    var openLi = panels.filter(function (li) { return li.classList.contains("open"); })[0];
    if (openLi) { setOpen(openLi, false); trigger(openLi).focus(); }
    else if (menu.classList.contains("open")) { setMenu(false); toggle.focus(); }
  });
  document.addEventListener("click", function (ev) {
    if (!nav.contains(ev.target)) { closeAll(null); if (phone.matches) setMenu(false); }
  });
  // Following a link inside the phone menu (same-page anchors) closes the menu.
  menu.addEventListener("click", function (ev) {
    if (phone.matches && ev.target.closest && ev.target.closest("a")) setMenu(false);
  });
})();

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
    }).then// Sentrigis website: "Request a demo" form. Sends the form as JSON to
// POST /api/contact and shows the result in place (no page reload). Without
// JavaScript the form posts normally and the server redirects to
// /#contact-sent or /#contact-error (shown by CSS :target).
(function () {
      button.disabled = false;
      button.textContent = label;
    });
  });
})();
