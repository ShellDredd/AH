/** @file DOM manipulation utilities */

export function el(tag, attrs = {}, children = []) {
  const element = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === 'className') element.className = value;
    else if (key === 'textContent') element.textContent = value;
    else if (key.startsWith('on') && typeof value === 'function') {
      element.addEventListener(key.slice(2).toLowerCase(), value);
    } else if (key === 'dataset') {
      for (const [dk, dv] of Object.entries(value)) element.dataset[dk] = dv;
    } else {
      element.setAttribute(key, value);
    }
  }
  for (const child of children) {
    if (typeof child === 'string') element.appendChild(document.createTextNode(child));
    else if (child) element.appendChild(child);
  }
  return element;
}

export function clearElement(element) {
  while (element.firstChild) element.removeChild(element.firstChild);
}

export function showElement(element) {
  element.classList.remove('hidden');
}

export function hideElement(element) {
  element.classList.add('hidden');
}

export async function sendMessage(type, data = {}) {
  return browser.runtime.sendMessage({ type, ...data });
}

export function onClick(element, handler) {
  element.addEventListener('click', handler);
  return element;
}
