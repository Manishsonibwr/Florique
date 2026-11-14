// Run once:  node fill-business.js
// Reads your details from business.json and writes them into the contact, legal and footer text of every page.
// Example values:
//   BUSINESS_NAME  "The Florique (your registered business name)"
//   ADDRESS        "Shop 12, Main Market, Sector 18, Noida, Uttar Pradesh 201301"
//   CITY           "Noida"            (courts used for legal disputes)
//   PHONE          "+91 98765 43210"
//   EMAIL          "hello@yourdomain.com"
//   HOURS          "Open daily, 9 AM to 8 PM"
const fs = require('fs');
const path = require('path');

const dir = path.join(__dirname, 'public');
const values = JSON.parse(fs.readFileSync(path.join(__dirname, 'business.json'), 'utf8'));

const empty = Object.keys(values).filter((k) => !String(values[k]).trim());
if (empty.length) {
  console.error('Please fill in these fields in business.json first: ' + empty.join(', '));
  process.exit(1);
}

const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
let changed = 0;
for (const file of fs.readdirSync(dir).filter((f) => f.endsWith('.html') && f !== 'admin.html')) {
  const p = path.join(dir, file);
  let html = fs.readFileSync(p, 'utf8');
  const before = html;
  for (const [key, val] of Object.entries(values)) {
    html = html.split('{{' + key + '}}').join(esc(val));
  }
  if (html !== before) { fs.writeFileSync(p, html); changed++; }
}
// tel: links should not contain spaces
for (const file of fs.readdirSync(dir).filter((f) => f.endsWith('.html'))) {
  const p = path.join(dir, file);
  const html = fs.readFileSync(p, 'utf8');
  const fixed = html.replace(/href="tel:([^"]+)"/g, (m, n) => 'href="tel:' + n.replace(/\s+/g, '') + '"');
  if (fixed !== html) fs.writeFileSync(p, fixed);
}
const left = fs.readdirSync(dir).filter((f) => f.endsWith('.html') && /\{\{[A-Z_]+\}\}/.test(fs.readFileSync(path.join(dir, f), 'utf8')));
console.log('Updated ' + changed + ' page(s).' + (left.length ? ' Still has placeholders: ' + left.join(', ') : ' All placeholders filled.'));
