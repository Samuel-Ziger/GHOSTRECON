import { createElement, type CSSProperties, type ReactNode, type SyntheticEvent } from 'react';

const BOOLEAN_ATTRIBUTES = new Set([
  'allowfullscreen',
  'async',
  'autofocus',
  'checked',
  'controls',
  'default',
  'defer',
  'disabled',
  'formnovalidate',
  'hidden',
  'loop',
  'multiple',
  'muted',
  'nomodule',
  'novalidate',
  'open',
  'playsinline',
  'readonly',
  'required',
  'reversed',
  'selected',
]);

const ATTRIBUTE_NAMES: Record<string, string> = {
  acceptcharset: 'acceptCharset',
  autocomplete: 'autoComplete',
  autofocus: 'autoFocus',
  cellpadding: 'cellPadding',
  cellspacing: 'cellSpacing',
  charset: 'charSet',
  class: 'className',
  colspan: 'colSpan',
  contenteditable: 'contentEditable',
  crossorigin: 'crossOrigin',
  datetime: 'dateTime',
  enctype: 'encType',
  fillrule: 'fillRule',
  'fill-rule': 'fillRule',
  for: 'htmlFor',
  formaction: 'formAction',
  formenctype: 'formEncType',
  formmethod: 'formMethod',
  formnovalidate: 'formNoValidate',
  formtarget: 'formTarget',
  frameborder: 'frameBorder',
  hreflang: 'hrefLang',
  'http-equiv': 'httpEquiv',
  maxlength: 'maxLength',
  minlength: 'minLength',
  novalidate: 'noValidate',
  playsinline: 'playsInline',
  readonly: 'readOnly',
  referrerpolicy: 'referrerPolicy',
  rowspan: 'rowSpan',
  spellcheck: 'spellCheck',
  'stop-color': 'stopColor',
  'stop-opacity': 'stopOpacity',
  'stroke-linecap': 'strokeLinecap',
  'stroke-linejoin': 'strokeLinejoin',
  'stroke-width': 'strokeWidth',
  tabindex: 'tabIndex',
  usemap: 'useMap',
};

const EVENT_NAMES: Record<string, string> = {
  onblur: 'onBlur',
  onchange: 'onChange',
  onclick: 'onClick',
  onerror: 'onError',
  onfocus: 'onFocus',
  oninput: 'onInput',
  onkeydown: 'onKeyDown',
  onkeypress: 'onKeyPress',
  onkeyup: 'onKeyUp',
  onload: 'onLoad',
  onmousedown: 'onMouseDown',
  onmouseenter: 'onMouseEnter',
  onmouseleave: 'onMouseLeave',
  onmousemove: 'onMouseMove',
  onmouseout: 'onMouseOut',
  onmouseover: 'onMouseOver',
  onmouseup: 'onMouseUp',
  onsubmit: 'onSubmit',
};

type LegacyHandler = (this: EventTarget, event: Event) => unknown;
const HANDLER_CACHE = new Map<string, LegacyHandler>();

function legacyHandler(code: string) {
  let compiled = HANDLER_CACHE.get(code);
  if (!compiled) {
    // O template é código versionado e confiável. A função reproduz a semântica
    // de atributos onclick antigos enquanto os handlers são extraídos por domínio.
    compiled = new Function('event', code) as LegacyHandler;
    HANDLER_CACHE.set(code, compiled);
  }

  return (reactEvent: SyntheticEvent) => {
    const result = compiled!.call(reactEvent.currentTarget, reactEvent.nativeEvent);
    if (result === false) {
      reactEvent.preventDefault();
      reactEvent.stopPropagation();
    }
  };
}

function camelCaseStyleName(name: string): string {
  if (name.startsWith('--')) return name;
  const prefixed = name.trim().toLowerCase();
  const camel = prefixed.replace(/-([a-z])/g, (_match, letter: string) => letter.toUpperCase());
  return camel.startsWith('ms-') ? `ms${camel.slice(3)}` : camel;
}

export function parseInlineStyle(styleText: string): CSSProperties {
  const style: Record<string, string> = {};
  for (const declaration of styleText.split(';')) {
    const colon = declaration.indexOf(':');
    if (colon <= 0) continue;
    const name = declaration.slice(0, colon).trim();
    const value = declaration.slice(colon + 1).trim();
    if (!name || !value) continue;
    style[camelCaseStyleName(name)] = value;
  }
  return style as CSSProperties;
}

function selectedValue(element: Element): string | string[] | undefined {
  if (element.tagName.toLowerCase() !== 'select') return undefined;
  const selected = [...element.querySelectorAll(':scope > option[selected], :scope > optgroup > option[selected]')]
    .map((option) => option.getAttribute('value') ?? option.textContent ?? '');
  if (!selected.length) return undefined;
  return element.hasAttribute('multiple') ? selected : selected[0];
}

function elementProps(element: Element, key: string | number): Record<string, unknown> {
  const tagName = element.tagName.toLowerCase();
  const props: Record<string, unknown> = { key };

  for (const attribute of [...element.attributes]) {
    const rawName = attribute.name;
    const lowerName = rawName.toLowerCase();
    if (lowerName === 'style') {
      props.style = parseInlineStyle(attribute.value);
      continue;
    }
    const eventName = EVENT_NAMES[lowerName];
    if (eventName) {
      props[eventName] = legacyHandler(attribute.value);
      continue;
    }
    if (lowerName === 'selected') continue;
    if (lowerName === 'checked') {
      props.defaultChecked = true;
      continue;
    }
    if (lowerName === 'value' && (tagName === 'input' || tagName === 'textarea')) {
      props.defaultValue = attribute.value;
      continue;
    }
    const propName = ATTRIBUTE_NAMES[lowerName] || rawName;
    props[propName] = BOOLEAN_ATTRIBUTES.has(lowerName) ? true : attribute.value;
  }

  const initialSelectedValue = selectedValue(element);
  if (initialSelectedValue !== undefined) props.defaultValue = initialSelectedValue;
  if (tagName === 'textarea' && props.defaultValue === undefined) {
    props.defaultValue = element.textContent || '';
  }
  return props;
}

const VOID_ELEMENTS = new Set([
  'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
  'link', 'meta', 'param', 'source', 'track', 'wbr',
]);

const SVG_TAG_NAMES: Record<string, string> = {
  clippath: 'clipPath',
  foreignobject: 'foreignObject',
  lineargradient: 'linearGradient',
  radialgradient: 'radialGradient',
  textpath: 'textPath',
};

function reactTagName(element: Element): string {
  const name = element.localName || element.tagName;
  if (element.namespaceURI === 'http://www.w3.org/2000/svg') {
    return SVG_TAG_NAMES[name.toLowerCase()] || name;
  }
  return name.toLowerCase();
}

export type DomToReactOptions = {
  replaceElement?: (
    element: Element,
    key: string | number,
  ) => ReactNode | undefined;
  transformElement?: (
    element: Element,
    props: Record<string, unknown>,
    key: string | number,
  ) => Record<string, unknown>;
};

export function domNodeToReact(
  node: Node,
  key: string | number,
  options: DomToReactOptions = {},
): ReactNode {
  if (node.nodeType === Node.TEXT_NODE) return node.textContent;
  if (node.nodeType !== Node.ELEMENT_NODE) return null;

  const element = node as Element;
  const tagName = reactTagName(element);
  if (tagName === 'script') return null;
  const replacement = options.replaceElement?.(element, key);
  if (replacement !== undefined) return replacement;
  const initialProps = elementProps(element, key);
  const props = options.transformElement
    ? options.transformElement(element, initialProps, key)
    : initialProps;
  if (VOID_ELEMENTS.has(tagName) || tagName === 'textarea') {
    return createElement(tagName, props);
  }
  const children = [...element.childNodes]
    .map((child, index) => domNodeToReact(child, `${key}.${index}`, options));
  return createElement(tagName, props, ...children);
}

export function domChildrenToReact(
  parent: ParentNode,
  options: DomToReactOptions = {},
): ReactNode[] {
  return [...parent.childNodes].map((node, index) => domNodeToReact(node, index, options));
}
