// routes/admin.js (or routes/metrics.js)
const express = require("express");
const router = express.Router();
const EncryptedImage = require("../models/EncryptedMedia");

// Helper to format bytes nicely
const formatBytes = (bytes) => {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
};

router.get("/stats", async (req, res) => {
  try {
    // 1. Get global totals
    const totalFiles = await EncryptedImage.countDocuments();
    const sizeAggregation = await EncryptedImage.aggregate([
      { $group: { _id: null, total: { $sum: "$size" } } },
    ]);
    const totalSizeBytes = sizeAggregation[0]?.total || 0;

    // 2. Breakdown by Media Type (Image, Video, Audio)
    const mediaTypeBreakdown = await EncryptedImage.aggregate([
      {
        $group: {
          _id: "$mediaType",
          count: { $sum: 1 },
          size: { $sum: "$size" },
        },
      },
    ]);

    // 3. Breakdown by Encryption Type (Basic vs Steganography)
    const encryptionTypeBreakdown = await EncryptedImage.aggregate([
      { $group: { _id: "$encryptionType", count: { $sum: 1 } } },
    ]);

    // 4. Recent Activity Feed (Last 5 processed files)
    const recentActivity = await EncryptedImage.find()
      .sort({ uploadDate: -1 })
      .limit(5)
      .select(
        "originalName mediaType encryptionType chaoticMap uploadDate size status",
      );

    // Restructure aggregations into easy-to-read objects for the frontend
    const mediaStats = { image: 0, video: 0, audio: 0 };
    mediaTypeBreakdown.forEach((item) => {
      if (item._id) mediaStats[item._id] = item.count;
    });

    const typeStats = { basic: 0, steganography: 0 };
    encryptionTypeBreakdown.forEach((item) => {
      if (item._id) typeStats[item._id] = item.count;
    });

    res.json({
      success: true,
      stats: {
        totalFiles,
        totalSizeBytes,
        storageUsed: formatBytes(totalSizeBytes),
        breakdowns: {
          byMedia: mediaStats,
          byEncryption: typeStats,
        },
        recentActivity,
      },
    });
  } catch (error) {
    console.error("Stats Route Error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch dashboard statistics",
      details: error.message,
    });
  }
});

module.exports = router;
