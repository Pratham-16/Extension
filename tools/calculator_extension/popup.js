let current = '0', prev = '', op = null, fresh = false;

const result = document.getElementById('result');
const expr   = document.getElementById('expr');

function update(v) { result.textContent = v; }

document.querySelectorAll('.btn-num').forEach(btn => {
  btn.addEventListener('click', () => {
    const n = btn.textContent;
    if (fresh) { current = n; fresh = false; }
    else current = current === '0' ? n : current + n;
    update(current);
  });
});

document.getElementById('dot').addEventListener('click', () => {
  if (!current.includes('.')) current += '.';
  update(current);
});

const ops = { div: '/', mul: '*', sub: '-', add: '+' };
Object.entries(ops).forEach(([id, symbol]) => {
  document.getElementById(id).addEventListener('click', () => {
    if (op && !fresh) calculate(true);
    prev = current; op = symbol; fresh = true;
    const sym = { '+':'+', '-':'−', '*':'×', '/':'÷' }[symbol];
    expr.textContent = prev + ' ' + sym;
  });
});

document.getElementById('eq').addEventListener('click', () => calculate(false));

function calculate(chain) {
  if (!op || !prev) return;
  const a = parseFloat(prev), b = parseFloat(current);
  let r;
  if (op === '+') r = a + b;
  else if (op === '-') r = a - b;
  else if (op === '*') r = a * b;
  else if (op === '/') r = b === 0 ? 'Error' : a / b;
  if (!chain) {
    const sym = { '+':'+', '-':'−', '*':'×', '/':'÷' }[op];
    expr.textContent = `${prev} ${sym} ${current} =`;
    op = null;
  }
  current = r === 'Error' ? 'Error' : String(parseFloat(r.toFixed(10)));
  prev = ''; fresh = true;
  update(current);
}

document.getElementById('ac').addEventListener('click', () => {
  current = '0'; prev = ''; op = null; fresh = false;
  expr.textContent = ''; update('0');
});

document.getElementById('sign').addEventListener('click', () => {
  if (current !== '0') { current = String(-parseFloat(current)); update(current); }
});

document.getElementById('pct').addEventListener('click', () => {
  current = String(parseFloat(current) / 100); update(current);
});