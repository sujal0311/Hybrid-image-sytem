const express = require('express');
const router = express.Router();
const EncryptedImage = require('../models/EncryptedImage');

// Get all metrics
router.get('/all', async (req, res) => {
  try {
    const images = await EncryptedImage.find().sort({ uploadDate: -1 }).limit(100);
    
    if (images.length === 0) {
      return res.json({
        success: true,
        metrics: {
          count: 0,
          average: { encryptionTime: 0, entropy: 0, size: 0 },
          operations: []
        }
      });
    }

    const totalTime = images.reduce((sum, img) => sum + (img.metrics?.encryptionTime || 0), 0);
    const totalEntropy = images.reduce((sum, img) => sum + (img.metrics?.entropy?.encrypted || 0), 0);
    const totalSize = images.reduce((sum, img) => sum + img.size, 0);

    const recentOperations = images.slice(0, 10).map(img => ({
      id: img._id,
      name: img.originalName,
      size: img.size,
      time: img.metrics?.encryptionTime || 0,
      entropy: img.metrics?.entropy?.encrypted || 0,
      date: img.uploadDate,
      chaoticMap: img.chaoticMap
    }));

    res.json({
      success: true,
      metrics: {
        count: images.length,
        average: {
          encryptionTime: (totalTime / images.length).toFixed(2),
          entropy: (totalEntropy / images.length).toFixed(4),
          size: Math.round(totalSize / images.length)
        },
        operations: recentOperations
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get stats
router.get('/stats', async (req, res) => {
  try {
    const images = await EncryptedImage.find();
    
    const stats = {
      totalEncryptions: images.length,
      byChaoticMap: {},
      performanceBySize: {
        small: { count: 0, avgTime: 0, totalTime: 0 },
        medium: { count: 0, avgTime: 0, totalTime: 0 },
        large: { count: 0, avgTime: 0, totalTime: 0 }
      }
    };

    images.forEach(img => {
      const map = img.chaoticMap || 'logistic';
      stats.byChaoticMap[map] = (stats.byChaoticMap[map] || 0) + 1;

      const sizeKB = img.size / 1024;
      const time = img.metrics?.encryptionTime || 0;
      
      if (sizeKB < 100) {
        stats.performanceBySize.small.count++;
        stats.performanceBySize.small.totalTime += time;
      } else if (sizeKB < 1024) {
        stats.performanceBySize.medium.count++;
        stats.performanceBySize.medium.totalTime += time;
      } else {
        stats.performanceBySize.large.count++;
        stats.performanceBySize.large.totalTime += time;
      }
    });

    Object.keys(stats.performanceBySize).forEach(key => {
      const category = stats.performanceBySize[key];
      if (category.count > 0) {
        category.avgTime = (category.totalTime / category.count).toFixed(2);
      }
      delete category.totalTime;
    });

    res.json({ success: true, stats });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
