/* Local SVG icons: no font dependencies or remote assets. */
function icon(name) {
  if (name === 'mastercard') {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24'); svg.setAttribute('class', 'svg-icon brand-icon');
    const r = document.createElementNS(svg.namespaceURI, 'rect');
    r.setAttribute('x', '2'); r.setAttribute('y', '4'); r.setAttribute('width', '20'); r.setAttribute('height', '16'); r.setAttribute('rx', '3'); r.setAttribute('fill', '#252525');
    const c1 = document.createElementNS(svg.namespaceURI, 'circle');
    c1.setAttribute('cx', '9.5'); c1.setAttribute('cy', '12'); c1.setAttribute('r', '4.2'); c1.setAttribute('fill', '#eb001b');
    const c2 = document.createElementNS(svg.namespaceURI, 'circle');
    c2.setAttribute('cx', '14.5'); c2.setAttribute('cy', '12'); c2.setAttribute('r', '4.2'); c2.setAttribute('fill', '#f79e1b');
    const p = document.createElementNS(svg.namespaceURI, 'path');
    p.setAttribute('d', 'M12 8.9a4.2 4.2 0 0 0 0 6.2 4.2 4.2 0 0 0 0-6.2z'); p.setAttribute('fill', '#ff5f00');
    svg.append(r, c1, c2, p);
    return svg;
  }
  if (name === 'visa') {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24'); svg.setAttribute('class', 'svg-icon brand-icon');
    const r = document.createElementNS(svg.namespaceURI, 'rect');
    r.setAttribute('x', '2'); r.setAttribute('y', '4'); r.setAttribute('width', '20'); r.setAttribute('height', '16'); r.setAttribute('rx', '3'); r.setAttribute('fill', '#1434cb');
    const t = document.createElementNS(svg.namespaceURI, 'text');
    t.setAttribute('x', '12'); t.setAttribute('y', '15'); t.setAttribute('text-anchor', 'middle');
    t.setAttribute('font-family', 'system-ui,-apple-system,sans-serif'); t.setAttribute('font-weight', '900');
    t.setAttribute('font-style', 'italic'); t.setAttribute('font-size', '7.5'); t.setAttribute('fill', '#ffffff');
    t.setAttribute('letter-spacing', '0.5'); t.textContent = 'VISA';
    svg.append(r, t);
    return svg;
  }
  if (name === 'amex') {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24'); svg.setAttribute('class', 'svg-icon brand-icon');
    const r = document.createElementNS(svg.namespaceURI, 'rect');
    r.setAttribute('x', '2'); r.setAttribute('y', '4'); r.setAttribute('width', '20'); r.setAttribute('height', '16'); r.setAttribute('rx', '3'); r.setAttribute('fill', '#006fcf');
    const t = document.createElementNS(svg.namespaceURI, 'text');
    t.setAttribute('x', '12'); t.setAttribute('y', '14.5'); t.setAttribute('text-anchor', 'middle');
    t.setAttribute('font-family', 'system-ui,-apple-system,sans-serif'); t.setAttribute('font-weight', '900');
    t.setAttribute('font-size', '5.5'); t.setAttribute('fill', '#ffffff');
    t.setAttribute('letter-spacing', '0.3'); t.textContent = 'AMEX';
    svg.append(r, t);
    return svg;
  }
  if (name === 'discover') {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24'); svg.setAttribute('class', 'svg-icon brand-icon');
    const rect = document.createElementNS(svg.namespaceURI, 'rect');
    rect.setAttribute('x', '2'); rect.setAttribute('y', '4'); rect.setAttribute('width', '20'); rect.setAttribute('height', '16'); rect.setAttribute('rx', '3'); rect.setAttribute('fill', '#ffffff');
    const text = document.createElementNS(svg.namespaceURI, 'text');
    text.setAttribute('x', '11.5'); text.setAttribute('y', '14.2'); text.setAttribute('text-anchor', 'middle');
    text.setAttribute('font-family', 'system-ui,-apple-system,sans-serif'); text.setAttribute('font-weight', '900');
    text.setAttribute('font-size', '5.5'); text.setAttribute('fill', '#202020'); text.textContent = 'DISC';
    const arc = document.createElementNS(svg.namespaceURI, 'path');
    arc.setAttribute('d', 'M14.5 15.7a4.2 4.2 0 0 0 6-3.7'); arc.setAttribute('fill', 'none'); arc.setAttribute('stroke', '#f58220'); arc.setAttribute('stroke-width', '2.1');
    svg.append(rect, text, arc);
    return svg;
  }
  const paths = {
    vault: ['rect:3,3,18,18,2', 'circle:12,12,5', 'M12 7v3m5 2h-3m-2 5v-3m-5-2h3'],
    key: ['circle:8,15,5', 'm11.5 11.5 8-8L22 6l-2 2-2-2-2 2 2 2-3 3'],
    note: ['M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z', 'M14 2v6h6M8 13h8M8 17h8'],
    card: ['rect:2,4,20,16,2', 'M2 10h20M6 15h3'],
    block: ['circle:12,12,10', 'm4.9 4.9 14.2 14.2'],
    palette: ['M12 22a10 10 0 1 1 10-10c0 2.8-2.2 3-4 3h-2a2 2 0 0 0-1.5 3.3A2 2 0 0 1 12 22Z', 'circle:13.5,6.5,.6', 'circle:17.5,10.5,.6', 'circle:8.5,7.5,.6', 'circle:6.5,12.5,.6'],
    keyboard: ['rect:2,5,20,14,2', 'M6 9h.01M10 9h.01M14 9h.01M18 9h.01M8 13h.01M12 13h.01M16 13h.01M7 16h10'],
    shield: ['M20 13c0 5-3.5 7.5-7.7 8.9a1 1 0 0 1-.6 0C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.2-2.7a1.2 1.2 0 0 1 1.6 0C14.5 3.8 17 5 19 5a1 1 0 0 1 1 1Z'],
    // Globe: placeholder for a website without a favicon.
    globe: ['circle:12,12,9', 'M3 12h18', 'M12 3a14 14 0 0 1 0 18a14 14 0 0 1 0-18Z'],
    // Android robot: head with antennae and eyes over its body.
    android: ['M5 12a7 7 0 0 1 14 0Z', 'm7.5 6.2-1.5-2.2m10.5 2.2 1.5-2.2', 'circle:9.3,9.3,.6', 'circle:14.7,9.3,.6', 'M5 14h14v4.5a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2Z'],
    identity: ['circle:12,8,4', 'M4 21v-2a8 8 0 0 1 16 0v2'],
    terminal: ['rect:3,3,18,18,2', 'm7 8 4 4-4 4m6 0h4'],
    generator: ['M20 7v5h-5M4 17v-5h5', 'M6 6a8 8 0 0 1 14 6M4 12a8 8 0 0 0 14 6'],
    send: ['m22 2-7 20-4-9-9-4Z', 'M22 2 11 13'],
    health: ['M20.8 4.6a5.5 5.5 0 0 0-7.8 0L12 5.7l-1.1-1.1a5.5 5.5 0 0 0-7.8 7.8L12 21l8.8-8.6a5.5 5.5 0 0 0 0-7.8Z'],
    settings: ['circle:12,12,3', 'm9 3 1-2h4l1 2 3 2 2-.2 2 3.4-1.2 1.8v4l1.2 1.8-2 3.4-2-.2-3 2-1 2h-4l-1-2-3-2-2 .2-2-3.4L3.2 14v-4L2 8.2l2-3.4 2 .2Z'],
    'chevron-left': ['m15 5-7 7 7 7'],
    'chevron-down': ['m6 9 6 6 6-6'],
    upload: ['M21 15v4H3v-4', 'm7 8 5-5 5 5M12 3v12'],
    lock: ['rect:5,10,14,12,2', 'M8 10V6a4 4 0 0 1 8 0v4'],
    unlock: ['rect:5,10,14,12,2', 'M8 10V6a4 4 0 0 1 8 0'],
    fingerprint: ['M12 10a2 2 0 0 0-2 2c0 1-.1 2.5-.3 4', 'M14 13.1c0 2.4 0 6.4-1 8.9', 'M17.3 21c.1-.6.4-2.3.5-3', 'M2 12a10 10 0 0 1 18-6', 'M21.8 16c.2-2 .1-5.4 0-6', 'M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .3-2', 'M8.7 22c.2-.7.4-1.3.6-2', 'M9 6.8a6 6 0 0 1 9 5.2v2'],
    back: ['m12 5-7 7 7 7M5 12h15'],
    sidebar: ['rect:3,3,18,18,2', 'M9 3v18'],
    undo: ['M9 14 4 9l5-5', 'M4 9h10.5a5.5 5.5 0 0 1 5.5 5.5a5.5 5.5 0 0 1-5.5 5.5H11'],
    edit: ['m16 3 5 5-12 12-6 1 1-6Z', 'm14 5 5 5'],
    archive: ['rect:3,3,18,5,1', 'M5 8v13h14V8M10 12h4'],
    star: ['m12 3 2.8 5.7 6.2.9-4.5 4.4 1.1 6.2-5.6-3-5.6 3 1.1-6.2L3 9.6l6.2-.9Z'],
    trash: ['M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7m4-7v7'],
    copy: ['rect:8,8,13,13,2', 'M16 8V3H3v13h5'],
    // A filled-in form field with a text cursor.
    fill: ['rect:2,7,20,10,2', 'M6.5 12h.01M10 12h.01M13.5 12h.01', 'M17.5 9.5v5'],
    more: ['circle:12,5,1.5', 'circle:12,12,1.5', 'circle:12,19,1.5'],
    search: ['circle:10.5,10.5,7.5', 'm16 16 5 5'],
    filters: ['M4 3v5m0 4v9M12 3v9m0 4v5M20 3v2m0 4v12M1 8h6m2 8h6m2-11h6'],
    plus: ['M12 5v14M5 12h14'],
    popout: ['M14 3h7v7m0-7L10 14M10 3H3v18h18v-7'],
    folder: ['M3 5h6l2 3h10v12H3Z'],
    collections: ['m12 3 10 5-10 5L2 8Zm-10 9 10 5 10-5M2 16l10 5 10-5'],
    eye: ['M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z', 'circle:12,12,3'],
    'eye-off': ['M9.88 9.88a3 3 0 1 0 4.24 4.24', 'M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68', 'M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61', 'M2 2l20 20'],
    close: ['M18 6 6 18', 'm6 6 12 12'],
    check: ['m5 12 5 5L20 7'],
    info: ['circle:12,12,10', 'M12 11v5', 'M12 7h.01'],
    warning: ['M12 3 2.5 20h19Z', 'M12 9v4', 'M12 17h.01'],
    download: ['M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4', 'm7 10 5 5 5-5', 'M12 15V3'],
    refresh: ['M20 7v5h-5M4 17v-5h5', 'M6 6a8 8 0 0 1 14 6M4 12a8 8 0 0 0 14 6'],
  };
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  for (const [key, value] of Object.entries({ viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '1.8', 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true', focusable: 'false', class: 'svg-icon' })) svg.setAttribute(key, value);
  for (const data of paths[name] || paths.note) {
    let child;
    if (data.startsWith('rect:')) {
      child = document.createElementNS(svg.namespaceURI, 'rect');
      const values = data.slice(5).split(','); ['x', 'y', 'width', 'height', 'rx'].forEach((key, i) => child.setAttribute(key, values[i]));
    } else if (data.startsWith('circle:')) {
      child = document.createElementNS(svg.namespaceURI, 'circle');
      data.slice(7).split(',').forEach((v, i) => child.setAttribute(['cx', 'cy', 'r'][i], v));
    } else {
      child = document.createElementNS(svg.namespaceURI, 'path'); child.setAttribute('d', data);
    }
    svg.append(child);
  }
  return svg;
}
