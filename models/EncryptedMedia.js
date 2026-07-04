const mongoose = require("mongoose");

const encryptedImageSchema = new mongoose.Schema(
  {
    // Basic Information
    originalName: {
      type: String,
      required: true,
      trim: true,
    },
    encryptedName: {
      type: String,
      required: true,
      trim: true,
    },
    encryptedPath: {
      type: String,
      required: true,
    },
    originalPath: {
      type: String,
      default: "",
    },
    size: {
      type: Number,
      required: true,
      min: 0,
      // Optional: Max 1GB to prevent integer overflow/abuse
      max: 1073741824,
    },
    mimeType: {
      type: String,
      required: true,
    },

    // Media type: image, video, audio
    mediaType: {
      type: String,
      enum: ["image", "video", "audio"],
      default: "image",
    },

    // Encryption Configuration
    chaoticMap: {
      type: String,
      enum: ["logistic", "arnold", "tent", "henon"],
      default: "logistic",
    },
    encryptionType: {
      type: String,
      enum: ["basic", "steganography"],
      default: "basic",
    },

    // Upload date
    uploadDate: {
      type: Date,
      default: Date.now,
    },

    // Metrics
    metrics: {
      encryptionTime: { type: Number, default: 0 },
      processing_time: { type: Number, default: 0 }, // Alternative field name
      entropy: {
        original: { type: Number, default: 0 },
        encrypted: { type: Number, default: 0 },
      },
      npcr: { type: Number, default: 0 },
      uaci: { type: Number, default: 0 },
      psnr: { type: Number, default: 0 },
      mse: { type: Number, default: 0 },

      // Video-specific
      frames: { type: Number, default: 0 },
      fps: { type: Number, default: 0 },
      resolution: { type: String, default: "" },

      // Audio-specific
      duration: { type: Number, default: 0 }, // seconds
      sampleRate: { type: Number, default: 0 },
      channels: { type: Number, default: 0 },

      // Allow additional fields not explicitly defined
    },

    // Status
    status: {
      type: String,
      enum: ["pending", "processing", "completed", "failed"],
      default: "completed", // Keep as completed since saving happens post-encryption
    },
  },
  {
    timestamps: true, // Automatically manages createdAt and updatedAt
  },
);

// Indexes for fast dashboard aggregation
encryptedImageSchema.index({ uploadDate: -1 });
encryptedImageSchema.index({ chaoticMap: 1 });
encryptedImageSchema.index({ mediaType: 1 });

module.exports = mongoose.model("EncryptedMedia", encryptedImageSchema);
