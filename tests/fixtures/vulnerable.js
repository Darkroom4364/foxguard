// Vulnerable JavaScript file — triggers all 12 foxguard JS rules

const crypto = require("crypto");
const fs = require("fs");
const { exec } = require("child_process");

// 1. js/no-eval (Critical)
const userInput = "alert(1)";
eval(userInput);

// 2. js/no-hardcoded-secret (High)
const apiKey = "sk-live-abcdef123456";

// 3. js/no-sql-injection — string concat (Critical)
const userId = "1";
const query1 = "SELECT * FROM users WHERE id = " + userId;

// 4. js/no-sql-injection — template literal (Critical)
const query2 = `SELECT * FROM users WHERE id = ${userId}`;

// 5. js/no-xss-innerhtml (High)
const el = document.getElementById("app");
el.innerHTML = userInput;

// 6. js/no-command-injection (Critical)
exec(userInput);

// 7. js/no-document-write (High)
document.write("<h1>Hello</h1>");

// 8. js/no-open-redirect (Medium)
window.location.href = userInput;

// 9. js/no-weak-crypto (Medium)
const hash = crypto.createHash("md5");

// 10. js/no-path-traversal (High)
fs.readFileSync(`/data/${userInput}`);

// 11. js/no-prototype-pollution (High)
const obj = {};
const a = "__proto__";
const b = "polluted";
obj[a][b] = "pwned";

// 12. js/no-unsafe-regex (Medium)
const re = /(a+)+$/;

// 13. js/no-cors-star (Medium)
const cors = { origin: "*" };
