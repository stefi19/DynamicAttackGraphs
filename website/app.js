const navLinks = Array.from(document.querySelectorAll(".nav a"));
const sections = navLinks
  .map((link) => document.querySelector(link.getAttribute("href")))
  .filter(Boolean);

const observer = new IntersectionObserver(
  (entries) => {
    const visible = entries
      .filter((entry) => entry.isIntersecting)
      .sort((left, right) => right.intersectionRatio - left.intersectionRatio)[0];
    if (!visible) return;
    navLinks.forEach((link) => {
      link.classList.toggle("active", link.getAttribute("href") === `#${visible.target.id}`);
    });
  },
  { rootMargin: "-25% 0px -65% 0px", threshold: [0.1, 0.4, 0.7] },
);

sections.forEach((section) => observer.observe(section));

document.querySelectorAll("pre").forEach((block) => {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "copy-code";
  button.textContent = "Copy";
  button.addEventListener("click", async () => {
    const code = block.querySelector("code")?.textContent ?? "";
    await navigator.clipboard.writeText(code);
    button.textContent = "Copied";
    window.setTimeout(() => {
      button.textContent = "Copy";
    }, 1200);
  });
  block.appendChild(button);
});

const lightbox = document.querySelector(".lightbox");
const lightboxImage = lightbox?.querySelector("img");
const lightboxCaption = lightbox?.querySelector("p");
const lightboxClose = lightbox?.querySelector("button");

document.querySelectorAll("figure img").forEach((image) => {
  image.addEventListener("click", () => {
    if (!lightbox || !lightboxImage || !lightboxCaption) return;
    const caption = image.closest("figure")?.querySelector("figcaption")?.textContent ?? image.alt;
    lightboxImage.src = image.src;
    lightboxImage.alt = image.alt;
    lightboxCaption.textContent = caption;
    lightbox.hidden = false;
  });
});

function closeLightbox() {
  if (lightbox) lightbox.hidden = true;
}

lightboxClose?.addEventListener("click", closeLightbox);
lightbox?.addEventListener("click", (event) => {
  if (event.target === lightbox) closeLightbox();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeLightbox();
});
