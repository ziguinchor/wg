import "dotenv/config";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import Admin from "./models/Admin.js";

const MONGODB_URI = process.env.MONGODB_URI;
const username = process.argv[2];
const password = process.argv[3];

if (!MONGODB_URI) {
  console.error("Missing MONGODB_URI");
  process.exit(1);
}

if (!username || !password) {
  console.error("Usage: node scripts/create-admin.js <username> <password>");
  process.exit(1);
}

async function main() {
  await mongoose.connect(MONGODB_URI);

  const existing = await Admin.findOne({ username }).lean();
  if (existing) {
    console.error(`Admin "${username}" already exists`);
    process.exit(1);
  }

  const passwordHash = bcrypt.hashSync(password, 10);

  await Admin.create({
    username,
    passwordHash,
    role: "admin",
    isActive: true
  });

  console.log(`Admin "${username}" created successfully`);
  await mongoose.disconnect();
}

main().catch((err) => {
  console.error("Failed to create admin:", err.message);
  process.exit(1);
});