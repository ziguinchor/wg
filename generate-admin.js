import bcrypt from "bcryptjs";

const password = process.argv[2];

if (!password) {
  console.log("Usage: node generate-admin.js <password>");
  process.exit(1);
}

const hash = bcrypt.hashSync(password, 10);

console.log("Password:", password);
console.log("Bcrypt hash:", hash);