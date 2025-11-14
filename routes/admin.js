const express = require('express');
const router = express.Router();
const EncryptedImage = require('../models/EncryptedImage');

router.get('/stats', async (req, res) => {
  try {
    const totalImages = await EncryptedImage.countDocuments();
    const totalSize = await EncryptedImage.aggregate([
      { $group: { _id: null, total: { $sum: '$size' } } }
    ]);

    res.json({
      success: true,
      stats: {
        totalImages,
        totalSize: totalSize[0]?.total || 0,
        storageUsed: ((totalSize[0]?.total || 0) / 1024 / 1024).toFixed(2) + ' MB'
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
