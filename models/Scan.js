const mongoose = require("mongoose");

const ScanSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    type: {
      type: String,
      enum: ["SMS", "Email", "Website", "QR Code", "Voice", "WhatsApp"],
      required: true,
    },
    input: {
      type: String,
      required: true,
      trim: true,
    },
    verdict: {
      type: String,
      enum: ["Safe", "Suspicious", "Dangerous"],
      required: true,
    },
    score: {
      type: Number,
      min: 0,
      max: 100,
      required: true,
    },
    reasons: {
      type: [String],
      default: [],
    },
  },
  { timestamps: true }
);

ScanSchema.index({ user: 1, createdAt: -1 });

module.exports = mongoose.model("Scan", ScanSchema);
