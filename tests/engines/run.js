// Reads cases (JSON) from the file named in argv, prints each case's leftmost match per input.
const cases = JSON.parse(require('fs').readFileSync(process.argv[2], 'utf8'));
const out = cases.map(({ pattern, flags, inputs }) => {
  let r;
  try { r = new RegExp(pattern, flags); } catch (e) { return { error: String(e.message) }; }
  return { spans: inputs.map(s => { const m = r.exec(s); return m ? [m.index, m.index + m[0].length] : null; }) };
});
process.stdout.write(JSON.stringify(out));
