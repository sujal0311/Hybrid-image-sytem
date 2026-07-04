const express = require("express");
const router = express.Router();
const EncryptedImage = require("../models/EncryptedMedia");

// ═════════════════════════════════════════════════════════════════════════════
// GET /all - Overall Metrics & Recent Operations
// ═════════════════════════════════════════════════════════════════════════════
router.get("/all", async (req, res) => {
  try {
    // 1. FAST AGGREGATION: Let MongoDB do the math instead of loading all docs into RAM
    const statsAggregation = await EncryptedImage.aggregate([
      {
        $group: {
          _id: null,
          count: { $sum: 1 },
          // Handle both 'encryptionTime' (basic) and 'processing_time' (steganography)
          avgTime: {
            $avg: {
              $ifNull: [
                "$metrics.encryptionTime",
                { $ifNull: ["$metrics.processing_time", 0] },
              ],
            },
          },
          avgEntropy: {
            $avg: { $ifNull: ["$metrics.entropy.encrypted", 0] },
          },
          avgSize: { $avg: "$size" },
        },
      },
    ]);

    const stats = statsAggregation[0] || {
      count: 0,
      avgTime: 0,
      avgEntropy: 0,
      avgSize: 0,
    };

    // 2. Fetch ONLY the 10 most recent operations for the feed
    const recentDocs = await EncryptedImage.find()
      .sort({ uploadDate: -1 })
      .limit(10)
      .select(
        "originalName size metrics uploadDate chaoticMap mediaType encryptionType",
      );

    const recentOperations = recentDocs.map((doc) => ({
      id: doc._id,
      name: doc.originalName,
      mediaType: doc.mediaType || "image",
      encryptionType: doc.encryptionType || "basic",
      size: doc.size,
      time: doc.metrics?.encryptionTime || doc.metrics?.processing_time || 0,
      entropy: doc.metrics?.entropy?.encrypted || 0,
      date: doc.uploadDate,
      chaoticMap: doc.chaoticMap || "logistic",
    }));

    res.json({
      success: true,
      metrics: {
        count: stats.count,
        average: {
          encryptionTime: (stats.avgTime || 0).toFixed(2),
          entropy: (stats.avgEntropy || 0).toFixed(4),
          size: Math.round(stats.avgSize || 0),
        },
        operations: recentOperations,
      },
    });
  } catch (error) {
    console.error("Metrics /all Error:", error);
    res.status(500).json({ error: error.message });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// GET /stats - Deep Dive Dashboard Analytics
// ═════════════════════════════════════════════════════════════════════════════
router.get("/stats", async (req, res) => {
  try {
    const totalEncryptions = await EncryptedImage.countDocuments();

    // 1. Group by Chaotic Map
    const mapAgg = await EncryptedImage.aggregate([
      {
        $group: {
          _id: { $ifNull: ["$chaoticMap", "logistic"] },
          count: { $sum: 1 },
        },
      },
    ]);
    const byChaoticMap = {};
    mapAgg.forEach((item) => {
      byChaoticMap[item._id] = item.count;
    });

    // 2. Group by Media Type (Image, Video, Audio)
    const mediaAgg = await EncryptedImage.aggregate([
      {
        $group: {
          _id: { $ifNull: ["$mediaType", "image"] },
          count: { $sum: 1 },
        },
      },
    ]);
    const byMediaType = {};
    mediaAgg.forEach((item) => {
      byMediaType[item._id] = item.count;
    });

    // 3. Size Performance Bucketing via Database Aggregation
    // This entirely prevents the RAM crash from looping huge datasets in Node.js
    const sizeAgg = await EncryptedImage.aggregate([
      {
        $project: {
          sizeKB: { $divide: ["$size", 1024] },
          time: {
            $ifNull: [
              "$metrics.encryptionTime",
              { $ifNull: ["$metrics.processing_time", 0] },
            ],
          },
        },
      },
      {
        $project: {
          bucket: {
            $switch: {
              branches: [
                { case: { $lt: ["$sizeKB", 100] }, then: "small" }, // < 100 KB
                { case: { $lt: ["$sizeKB", 5000] }, then: "medium" }, // 100 KB - 5 MB
              ],
              default: "large", // > 5 MB
            },
          },
          time: 1,
        },
      },
      {
        $group: {
          _id: "$bucket",
          count: { $sum: 1 },
          avgTime: { $avg: "$time" },
        },
      },
    ]);

    // Setup default structure
    const performanceBySize = {
      small: { count: 0, avgTime: "0.00" },
      medium: { count: 0, avgTime: "0.00" },
      large: { count: 0, avgTime: "0.00" },
    };

    // Populate with actual data
    sizeAgg.forEach((bucket) => {
      if (performanceBySize[bucket._id]) {
        performanceBySize[bucket._id].count = bucket.count;
        performanceBySize[bucket._id].avgTime = (bucket.avgTime || 0).toFixed(
          2,
        );
      }
    });

    res.json({
      success: true,
      stats: {
        totalEncryptions,
        byChaoticMap,
        byMediaType,
        performanceBySize,
      },
    });
  } catch (error) {
    console.error("Metrics /stats Error:", error);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
