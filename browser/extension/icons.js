/* Local SVG icons: no font dependencies or remote assets. */
function icon(name) {
  const paths = {
    vault: ['rect:3,3,18,18,2', 'circle:12,12,5', 'M12 7v3m5 2h-3m-2 5v-3m-5-2h3'],
    key: ['circle:8,15,5', 'm11.5 11.5 8-8L22 6l-2 2-2-2-2 2 2 2-3 3'],
    note: ['M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z', 'M14 2v6h6M8 13h8M8 17h8'],
    card: ['rect:2,4,20,16,2', 'M2 10h20M6 15h3'],
    identity: ['circle:12,8,4', 'M4 21v-2a8 8 0 0 1 16 0v2'],
    terminal: ['rect:3,3,18,18,2', 'm7 8 4 4-4 4m6 0h4'],
    generator: ['M20 7v5h-5M4 17v-5h5', 'M6 6a8 8 0 0 1 14 6M4 12a8 8 0 0 0 14 6'],
    send: ['m22 2-7 20-4-9-9-4Z', 'M22 2 11 13'],
    health: ['M20.8 4.6a5.5 5.5 0 0 0-7.8 0L12 5.7l-1.1-1.1a5.5 5.5 0 0 0-7.8 7.8L12 21l8.8-8.6a5.5 5.5 0 0 0 0-7.8Z'],
    settings: ['circle:12,12,3', 'm9 3 1-2h4l1 2 3 2 2-.2 2 3.4-1.2 1.8v4l1.2 1.8-2 3.4-2-.2-3 2-1 2h-4l-1-2-3-2-2 .2-2-3.4L3.2 14v-4L2 8.2l2-3.4 2 .2Z'],
    back: ['m12 5-7 7 7 7M5 12h15'],
    edit: ['m16 3 5 5-12 12-6 1 1-6Z', 'm14 5 5 5'],
    archive: ['rect:3,3,18,5,1', 'M5 8v13h14V8M10 12h4'],
    star: ['m12 3 2.8 5.7 6.2.9-4.5 4.4 1.1 6.2-5.6-3-5.6 3 1.1-6.2L3 9.6l6.2-.9Z'],
    trash: ['M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7m4-7v7'],
    copy: ['rect:8,8,13,13,2', 'M16 8V3H3v13h5'],
    fill: ['M4 4v8h15m-5-5 5 5-5 5'],
    more: ['circle:12,5,1', 'circle:12,12,1', 'circle:12,19,1'],
    search: ['circle:10.5,10.5,7.5', 'm16 16 5 5'],
    filters: ['M4 3v5m0 4v9M12 3v9m0 4v5M20 3v2m0 4v12M1 8h6m2 8h6m2-11h6'],
    plus: ['M12 5v14M5 12h14'],
    popout: ['M14 3h7v7m0-7L10 14M10 3H3v18h18v-7'],
    folder: ['M3 5h6l2 3h10v12H3Z'],
    collections: ['m12 3 10 5-10 5L2 8Zm-10 9 10 5 10-5M2 16l10 5 10-5'],
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
