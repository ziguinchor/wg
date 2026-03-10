import mongoose from "mongoose";

const adminSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      minlength: 3,
      maxlength: 50
    },
    passwordHash: {
      type: String,
      required: true
    },
    role: {
      type: String,
      default: "admin"
    },
    isActive: {
      type: Boolean,
      default: true
    }
  },
  {
    timestamps: true,
    versionKey: false,
    collection: "admins"
  }
);

adminSchema.index({ username: 1 }, { unique: true });

const Admin = mongoose.model("Admin", adminSchema);

export default Admin;