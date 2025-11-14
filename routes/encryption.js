// routes/encryption.js - OPTIMIZED FOR RENDER
const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { exec } = require('child_process');
const os = require('os');
const EncryptedImage = require('../models/EncryptedImage');

// ✅ RENDER-COMPATIBLE PYTHON DETECTION
const getPythonCommand = () => {
  if (process.env.RENDER) {
    return 'python3'; // Render uses python3
  }
  return os.platform() === 'win32' ? 'python' : 'python3';
};

const PYTHON_CMD = getPythonCommand();

// ✅ HELPER: RUN PYTHON SCRIPTS WITH PROPER ERROR HANDLING
const runPythonScript = (scriptPath, args = []) => {
  return new Promise((resolve, reject) => {
    const argsString = args.map(arg => `"${arg}"`).join(' ');
    const command = `${PYTHON_CMD} "${scriptPath}" ${argsString}`;
    
    console.log('🐍 Running:', command);
    
    exec(command, {
      timeout: 30000,
      maxBuffer: 50 * 1024 * 1024,
      encoding: 'utf-8'
    }, (error, stdout, stderr) => {
      if (error) {
        console.error('❌ Python error:', stderr);
        reject(new Error(stderr || error.message));
        return;
      }
      
      try {
        const result = JSON.parse(stdout.trim());
        resolve(result);
      } catch (parseError) {
        console.error('❌ Parse error:', stdout);
        reject(new Error(`Failed to parse: ${stdout}`));
      }
    });
  });
};

// ✅ RENDER-COMPATIBLE MULTER CONFIGURATION
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // Use /tmp for Render's ephemeral storage
    const uploadDir = process.env.RENDER 
      ? path.join('/tmp', 'uploads', 'original')
      : path.join(__dirname, '../uploads/original');
    
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    cb(null, true);
  }
});

// ==================== ENCRYPT WITH METRICS ====================
router.post('/encrypt', upload.single('image'), async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { key, chaoticMap = 'logistic' } = req.body;
    
    if (!req.file) {
      return res.status(400).json({ error: 'No image file uploaded' });
    }
    
    if (!key || key.length < 8) {
      return res.status(400).json({ error: 'Key must be at least 8 characters' });
    }

    const imagePath = req.file.path;
    const originalName = req.file.originalname;
    const baseName = path.basename(originalName, path.extname(originalName));
    const timestamp = Date.now();
    const encryptedName = `${baseName}_encrypted_${timestamp}.bin`;
    
    const encryptionScript = path.join(__dirname, '../python/encryption.py');
    const metricsScript = path.join(__dirname, '../python/metrics_analyzer.py');

    console.log('🔒 Step 1: Encrypting:', originalName);
    console.log('📍 Python command:', PYTHON_CMD);
    console.log('📍 Script path:', encryptionScript);

    // ✅ STEP 1: Encrypt the image
    const encryptResult = await runPythonScript(encryptionScript, [
      'encrypt',
      imagePath,
      key,
      chaoticMap
    ]);
    
    if (!encryptResult.success) {
      return res.status(500).json({ 
        error: encryptResult.error || 'Encryption failed' 
      });
    }
    
    const encryptionTime = Date.now() - startTime;
    const encryptedPath = encryptResult.encrypted_path;
    
    // ✅ STEP 2: Calculate security metrics
    console.log('📊 Step 2: Calculating metrics...');
    let calculatedMetrics = {
      encryptionTime: encryptionTime,
      entropy: { original: 0, encrypted: 0 },
      NPCR: 0,
      UACI: 0,
      correlation: 0,
      PSNR: 0,
      MSE: 0
    };
    
    try {
      const metricsResult = await runPythonScript(metricsScript, [
        'encryption',
        imagePath,
        encryptedPath
      ]);
      
      if (metricsResult.success) {
        calculatedMetrics = {
          encryptionTime: encryptionTime,
          entropy: metricsResult.entropy || { original: 0, encrypted: 0 },
          NPCR: metricsResult.npcr || 0,
          UACI: metricsResult.uaci || 0,
          correlation: metricsResult.correlation || 0,
          PSNR: 0,
          MSE: 0
        };
        console.log('✅ Metrics calculated:', {
          NPCR: calculatedMetrics.NPCR,
          UACI: calculatedMetrics.UACI,
          entropy: calculatedMetrics.entropy.encrypted
        });
      }
    } catch (metricsError) {
      console.warn('⚠️ Metrics calculation failed, using defaults:', metricsError.message);
    }

    // ✅ STEP 3: Save to database
    const newImage = new EncryptedImage({
      originalName: originalName,
      encryptedName: encryptedName,
      encryptedPath: encryptedPath,
      originalPath: imagePath,
      size: req.file.size,
      mimeType: req.file.mimetype,
      chaoticMap: chaoticMap,
      encryptionType: 'basic',
      status: 'completed',
      metrics: calculatedMetrics
    });

    await newImage.save();

    console.log('✅ Encryption successful with metrics, ID:', newImage._id);

    res.json({
      success: true,
      message: 'Image encrypted successfully',
      imageId: newImage._id,
      encryptedName: encryptedName,
      encryptionTime: encryptionTime,
      metrics: calculatedMetrics
    });
    
  } catch (error) {
    console.error('❌ Server error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== DECRYPT ====================
router.post('/decrypt', upload.single('image'), async (req, res) => {
  try {
    const { key } = req.body;
    
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    if (!key) {
      return res.status(400).json({ error: 'Decryption key required' });
    }

    const encryptedPath = req.file.path;
    const pythonScript = path.join(__dirname, '../python/encryption.py');

    console.log('🔓 Decrypting file...');

    const result = await runPythonScript(pythonScript, [
      'decrypt',
      encryptedPath,
      key
    ]);

    if (!result.success) {
      // Clean up
      try {
        fs.unlinkSync(encryptedPath);
      } catch (cleanupError) {
        console.error('Cleanup error:', cleanupError);
      }
      
      return res.status(500).json({ 
        error: result.error || 'Decryption failed',
        hint: 'Make sure you are using the correct encryption key'
      });
    }

    const decryptedPath = result.decrypted_path;
    
    console.log('✅ Decryption successful');
    
    if (!fs.existsSync(decryptedPath)) {
      throw new Error('Decrypted file not found');
    }
    
    // Send file for download
    res.download(decryptedPath, 'decrypted_image.png', (downloadError) => {
      if (downloadError) {
        console.error('❌ Download error:', downloadError);
      }
      
      // Clean up files
      try {
        if (fs.existsSync(encryptedPath)) {
          fs.unlinkSync(encryptedPath);
        }
        if (fs.existsSync(decryptedPath)) {
          fs.unlinkSync(decryptedPath);
        }
        console.log('✅ Cleanup completed');
      } catch (cleanupError) {
        console.error('⚠️ Cleanup error:', cleanupError);
      }
    });

  } catch (error) {
    console.error('❌ Server error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== STEGANOGRAPHY ENCRYPT WITH METRICS ====================
router.post('/encrypt-stego', upload.fields([
  { name: 'secretImage', maxCount: 1 },
  { name: 'coverImage', maxCount: 1 }
]), async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { key, chaoticMap = 'logistic' } = req.body;
    
    if (!req.files || !req.files.secretImage || !req.files.coverImage) {
      return res.status(400).json({ error: 'Both secret and cover images required' });
    }
    
    if (!key || key.length < 8) {
      return res.status(400).json({ error: 'Key must be at least 8 characters' });
    }
    
    const secretPath = req.files.secretImage[0].path;
    const coverPath = req.files.coverImage[0].path;
    
    const stegoScript = path.join(__dirname, '../python/steganography.py');
    const metricsScript = path.join(__dirname, '../python/metrics_analyzer.py');

    console.log('🎭 Step 1: Steganography encryption...');

    // Step 1: Create stego image
    const stegoResult = await runPythonScript(stegoScript, [
      'encrypt',
      secretPath,
      coverPath,
      key,
      chaoticMap
    ]);
    
    if (!stegoResult.success) {
      return res.status(500).json({ 
        error: stegoResult.error || 'Steganography failed' 
      });
    }
    
    const encryptionTime = Date.now() - startTime;
    const stegoPath = stegoResult.stego_path;
    const stegoName = path.basename(stegoPath);
    
    // Step 2: Calculate PSNR and MSE
    console.log('📊 Step 2: Calculating stego metrics...');
    let calculatedMetrics = {
      encryptionTime: encryptionTime,
      entropy: { original: 0, encrypted: 0 },
      NPCR: 0,
      UACI: 0,
      correlation: 0,
      PSNR: 0,
      MSE: 0
    };
    
    try {
      const metricsResult = await runPythonScript(metricsScript, [
        'steganography',
        coverPath,
        stegoPath
      ]);
      
      if (metricsResult.success) {
        calculatedMetrics.PSNR = metricsResult.psnr || 0;
        calculatedMetrics.MSE = metricsResult.mse || 0;
        console.log('✅ Stego metrics:', { 
          PSNR: calculatedMetrics.PSNR, 
          MSE: calculatedMetrics.MSE 
        });
      }
    } catch (metricsError) {
      console.warn('⚠️ Stego metrics failed, using defaults:', metricsError.message);
    }
    
    const newImage = new EncryptedImage({
      originalName: req.files.secretImage[0].originalname,
      encryptedName: stegoName,
      encryptedPath: stegoPath,
      originalPath: secretPath,
      size: req.files.secretImage[0].size,
      mimeType: req.files.secretImage[0].mimetype,
      chaoticMap: chaoticMap,
      encryptionType: 'steganography',
      status: 'completed',
      metrics: calculatedMetrics
    });

    await newImage.save();

    console.log('✅ Steganography successful with metrics');

    res.json({
      success: true,
      message: 'Triple-layer steganography successful',
      imageId: newImage._id,
      stegoName: stegoName,
      encryptionTime: encryptionTime,
      metrics: calculatedMetrics
    });
    
  } catch (error) {
    console.error('❌ Server error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== STEGANOGRAPHY DECRYPT ====================
router.post('/decrypt-stego', upload.single('image'), async (req, res) => {
  try {
    const { key } = req.body;
    
    if (!req.file) {
      return res.status(400).json({ error: 'No stego image uploaded' });
    }
    
    if (!key) {
      return res.status(400).json({ error: 'Decryption key required' });
    }
    
    const stegoPath = req.file.path;
    const pythonScript = path.join(__dirname, '../python/steganography.py');

    console.log('🎭 Extracting from steganography...');

    const result = await runPythonScript(pythonScript, [
      'decrypt',
      stegoPath,
      key
    ]);

    if (!result.success) {
      try {
        fs.unlinkSync(stegoPath);
      } catch (cleanupError) {
        console.error('Cleanup error:', cleanupError);
      }
      
      return res.status(500).json({ 
        error: result.error || 'Extraction failed',
        hint: 'Make sure you are using the correct encryption key'
      });
    }

    const decryptedPath = result.decrypted_path;
    
    console.log('✅ Extraction successful');
    
    if (!fs.existsSync(decryptedPath)) {
      throw new Error('Extracted file not found');
    }
    
    res.download(decryptedPath, 'extracted_secret.png', (downloadError) => {
      if (downloadError) {
        console.error('❌ Download error:', downloadError);
      }
      
      try {
        if (fs.existsSync(stegoPath)) {
          fs.unlinkSync(stegoPath);
        }
        if (fs.existsSync(decryptedPath)) {
          fs.unlinkSync(decryptedPath);
        }
        console.log('✅ Cleanup completed');
      } catch (cleanupError) {
        console.error('⚠️ Cleanup error:', cleanupError);
      }
    });

  } catch (error) {
    console.error('❌ Server error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== GET ALL IMAGES ====================
router.get('/images', async (req, res) => {
  try {
    const images = await EncryptedImage.find()
      .sort({ uploadDate: -1 })
      .limit(100);
    res.json({ success: true, images });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== DELETE IMAGE ====================
router.delete('/images/:id', async (req, res) => {
  try {
    const image = await EncryptedImage.findByIdAndDelete(req.params.id);
    if (!image) {
      return res.status(404).json({ error: 'Image not found' });
    }
    
    // Clean up files
    if (fs.existsSync(image.encryptedPath)) {
      fs.unlinkSync(image.encryptedPath);
    }
    if (image.originalPath && fs.existsSync(image.originalPath)) {
      fs.unlinkSync(image.originalPath);
    }
    
    res.json({ success: true, message: 'Image deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== DOWNLOAD ENCRYPTED FILE ====================
router.get('/download/:id', async (req, res) => {
  try {
    const image = await EncryptedImage.findById(req.params.id);
    if (!image) {
      return res.status(404).json({ error: 'Image not found' });
    }
    res.download(image.encryptedPath, image.encryptedName);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== DOWNLOAD STEGO IMAGE ====================
router.get('/download-stego/:id', async (req, res) => {
  try {
    const image = await EncryptedImage.findById(req.params.id);
    if (!image) {
      return res.status(404).json({ error: 'Image not found' });
    }
    
    if (image.encryptionType !== 'steganography') {
      return res.status(400).json({ error: 'Not a steganography image' });
    }
    
    res.download(image.encryptedPath, 'stego_image.png');
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== DEBUG/TEST ROUTES ====================
router.get('/test-metrics', async (req, res) => {
  try {
    const metricsScript = path.join(__dirname, '../python/metrics_analyzer.py');
    
    res.json({
      success: true,
      message: 'Metrics script configuration',
      pythonPath: PYTHON_CMD,
      scriptPath: metricsScript,
      scriptExists: fs.existsSync(metricsScript),
      isRender: !!process.env.RENDER,
      environment: process.env.NODE_ENV || 'development'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

module.exports = router;
