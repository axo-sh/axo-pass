// Visibility checks for fields before a fill. A page can collect credentials
// through fields the user cannot see, so a fill writes only to fields that are
// rendered, on the page, large enough to read, and not covered.

/** Smallest width and height, in CSS pixels, of a field the user can read. */
const MIN_SIZE = 4;

/** Opacity below which an element counts as invisible. */
const MIN_OPACITY = 0.1;

/**
 * Window of the field's document. Its own constructors are used for
 * `instanceof`, since a field in another frame or test document fails the
 * check against the script's globals.
 */
type PageWindow = Window & typeof globalThis;

/** Whether `el` is a field the user can see. */
export const isVisible = (el: HTMLElement): boolean => {
  const win = el.ownerDocument.defaultView;
  if (!win || !el.isConnected) {
    return false;
  }
  if (!isRendered(el, win)) {
    return false;
  }

  const rect = el.getBoundingClientRect();
  if (rect.width < MIN_SIZE || rect.height < MIN_SIZE) {
    return false;
  }
  if (isOffPage(rect, el.ownerDocument, win)) {
    return false;
  }
  return !isCovered(el, rect, win);
};

/**
 * Whether `el` and every ancestor are displayed, visible, and opaque enough to
 * see. Opacity multiplies down the tree, so it is accumulated.
 */
const isRendered = (el: HTMLElement, win: PageWindow): boolean => {
  const own = win.getComputedStyle(el);
  if (own.visibility === 'hidden' || own.visibility === 'collapse') {
    return false;
  }

  let opacity = 1;
  for (let node: Element | null = el; node; node = node.parentElement) {
    if (node instanceof win.HTMLElement && node.hidden) {
      return false;
    }
    const style = win.getComputedStyle(node);
    if (style.display === 'none') {
      return false;
    }
    if (style.contentVisibility === 'hidden') {
      return false;
    }
    const value = parseFloat(style.opacity);
    if (!Number.isNaN(value)) {
      opacity *= value;
    }
    if (opacity < MIN_OPACITY) {
      return false;
    }
    if (isClippedAway(style)) {
      return false;
    }
  }
  return true;
};

/** Clip rules that hide an element entirely, as screen-reader-only styles do. */
const isClippedAway = (style: CSSStyleDeclaration): boolean => {
  // Engines without a property report `undefined` for it.
  const clip = (style.clip ?? '').replace(/\s/g, '');
  if (clip === 'rect(0,0,0,0)' || clip === 'rect(0px,0px,0px,0px)') {
    return true;
  }
  const clipPath = (style.clipPath ?? '').replace(/\s/g, '');
  return clipPath === 'inset(50%)' || clipPath === 'inset(100%)';
};

/**
 * Whether a box lies outside the page, where no scrolling brings it into view,
 * such as a field placed at `left: -9999px`.
 */
const isOffPage = (rect: DOMRect, doc: Document, win: PageWindow): boolean => {
  const left = rect.left + win.scrollX;
  const top = rect.top + win.scrollY;
  const width = Math.max(doc.documentElement.scrollWidth, win.innerWidth);
  const height = Math.max(doc.documentElement.scrollHeight, win.innerHeight);
  return left + rect.width <= 0 || top + rect.height <= 0 || left >= width || top >= height;
};

/**
 * Whether another element covers the field at each of its sample points. Only
 * points inside the viewport can be tested, so a field scrolled out of view is
 * not checked. A label of the field may cover it, as floating labels do.
 */
const isCovered = (el: HTMLElement, rect: DOMRect, win: PageWindow): boolean => {
  const doc = el.ownerDocument;
  if (typeof doc.elementFromPoint !== 'function') {
    return false;
  }
  const points = [
    [rect.left + rect.width / 2, rect.top + rect.height / 2],
    [rect.left + Math.min(8, rect.width / 4), rect.top + rect.height / 2],
    [rect.right - Math.min(8, rect.width / 4), rect.top + rect.height / 2],
  ];
  let tested = 0;
  for (const [x, y] of points) {
    if (x < 0 || y < 0 || x >= win.innerWidth || y >= win.innerHeight) {
      continue;
    }
    tested++;
    const hit = doc.elementFromPoint(x, y);
    if (hit && isPartOf(hit, el, win)) {
      return false;
    }
  }
  return tested > 0;
};

const isPartOf = (hit: Element, el: HTMLElement, win: PageWindow): boolean => {
  if (hit === el || el.contains(hit)) {
    return true;
  }
  const label: Element | null = hit.closest('label');
  return label instanceof win.HTMLLabelElement && label.control === el;
};
