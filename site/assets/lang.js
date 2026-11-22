// The home page opens in the visitor's language: the one they picked on this site
// before, else the first of the browser's languages the site has. Picking a language
// in the header remembers it, so going back to English does not bounce.
(function () {
  var KEY = "jt-oz-bridge-lang";
  var PAGES = { en: "", zh: "zh-tw/", ja: "ja/" };

  function family(tag) {
    var base = String(tag || "").toLowerCase().split("-")[0];
    return Object.prototype.hasOwnProperty.call(PAGES, base) ? base : null;
  }

  function stored() {
    try {
      return family(window.localStorage.getItem(KEY));
    } catch (error) {
      return null;
    }
  }

  if (document.documentElement.hasAttribute("data-language-home")) {
    var choice = stored();
    if (!choice) {
      var wanted = navigator.languages && navigator.languages.length
        ? navigator.languages
        : [navigator.language];
      for (var i = 0; i < wanted.length && !choice; i++) {
        choice = family(wanted[i]);
      }
    }
    if (choice && PAGES[choice]) {
      window.location.replace(PAGES[choice] + window.location.hash);
      return;
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    var links = document.querySelectorAll(".lang a[hreflang]");
    for (var i = 0; i < links.length; i++) {
      links[i].addEventListener("click", function (event) {
        try {
          window.localStorage.setItem(KEY, event.currentTarget.getAttribute("hreflang"));
        } catch (error) {
          // Private windows may refuse storage; the link still works.
        }
      });
    }
  });
})();
