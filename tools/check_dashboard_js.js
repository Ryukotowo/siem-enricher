// Синтаксическая проверка панели и расчёт шкалы дашборда.
const fs = require('fs');

const html = fs.readFileSync(process.argv[2], 'utf8');
const scriptStart = html.indexOf('function bucketKey');
const scriptEnd = html.indexOf('function connectStream');
const code = html.slice(scriptStart, scriptEnd);

new Function(code);
console.log('синтаксис JS: ок');

const events = [
  {ts: '2026-11-13T09:06:48Z', decision: 'allow'},
  {ts: '2026-11-13T09:16:48Z', decision: 'block'},
  {ts: '2026-11-13T09:36:48Z', decision: 'allow'},
];

const series = new Function('DATA', `
  const moments = DATA.map(e => new Date(e.ts || 0)).filter(d => !Number.isNaN(d.getTime()));
  const slots = 18;
  const slotMs = 10 * 60 * 1000;
  const latest = moments.length ? Math.max(...moments.map(d => d.getTime())) : Date.now();
  const startSlot = Math.floor(latest / slotMs) - slots + 1;
  const totals = new Array(slots).fill(0);
  for (const date of moments) {
    const index = Math.floor(date.getTime() / slotMs) - startSlot;
    if (index < 0 || index >= slots) continue;
    totals[index] += 1;
  }
  return {totals, latest};
`)(events);

console.log('слотов:', series.totals.length, '| ненулевых:', series.totals.filter(v => v > 0).length);
console.log('сумма событий в шкале:', series.totals.reduce((a, b) => a + b, 0));

const sparkCode = code.slice(0, code.indexOf('function topList'));
const single = new Function('series', 'color', 'max', sparkCode + '; return sparkline(series, color, max);')([5], '#B3261E', 5);
console.log('одиночная точка:', single.slice(0, 55));
