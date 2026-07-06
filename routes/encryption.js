const express = require("express");
const router = express.Router();
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const { exec } = require("child_process");
const os = require("os");
const EncryptedImage = require("../models/EncryptedMedia");

// ── Python Config ─────────────────────────────────────────────────────────────
const PYTHON_CMD = process.env.RENDER
  ? "python3"
  : os.platform() === "win32"
    ? "python"
    : "python3";

const SCRIPTS = {
  image: path.join(__dirname, "../python/encryption.py"),
  stego: path.join(__dirname, "../python/steganography.py"),
  audioStego: path.join(__dirname, "../python/audio_steganography.py"),
  videoStego: path.join(__dirname, "../python/video_steganography.py"),
  metrics: path.join(__dirname, "../python/metrics_analyzer.py"),
  video: path.join(__dirname, "../python/video_encryption.py"),
  audio: path.join(__dirname, "../python/audio_encryption.py"),
};

// ── Helper: Clean Metrics for Mongoose ────────────────────────────────────────
const cleanMetrics = (metrics) => {
  if (!metrics) return { encryptionTime: 0 };
  const cleaned = { ...metrics };

  // Ensure encryptionTime is a number
  if (cleaned.encryptionTime) {
    cleaned.encryptionTime = parseFloat(cleaned.encryptionTime) || 0;
  } else {
    cleaned.encryptionTime = 0;
  }

  // Handle PSNR edge cases
  if (cleaned.psnr === "inf" || cleaned.psnr === Infinity) {
    cleaned.psnr = 9999;
  } else if (cleaned.psnr && typeof cleaned.psnr === "string") {
    cleaned.psnr = parseFloat(cleaned.psnr.replace(/[^\d.]/g, "")) || 0;
  }

  return cleaned;
};

// ── Run Python ────────────────────────────────────────────────────────────────
const runPython = (scriptPath, args = []) =>
  new Promise((resolve, reject) => {
    const escaped = args
      .map((a) => `"${String(a).replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`)
      .join(" ");
    const cmd = `${PYTHON_CMD} "${scriptPath}" ${escaped}`;

    console.log("🐍 Running:", cmd);

    const child = exec(
      cmd,
      {
        timeout: 30 * 60 * 1000,
        maxBuffer: 2 * 1024 * 1024 * 1024,
        encoding: "utf-8",
      },
      (err, stdout, stderr) => {
        if (stderr) console.warn("Python stderr:", stderr.slice(0, 500));
        if (err) {
          if (err.killed) {
            return reject(
              new Error(
                `Process timeout after 30 minutes - file may be too large`,
              ),
            );
          }
          return reject(new Error(stderr || err.message));
        }

        try {
          resolve(JSON.parse(stdout.trim()));
        } catch {
          reject(
            new Error(`Invalid JSON from Python: ${stdout.slice(0, 300)}`),
          );
        }
      },
    );
    child.on("error", (err) =>
      reject(new Error(`Process error: ${err.message}`)),
    );
  });

// ── Helpers ───────────────────────────────────────────────────────────────────
const uploadDir = (sub) => {
  const base = process.env.RENDER ? "/tmp" : path.join(__dirname, "..");
  const dir = path.join(base, "uploads", sub);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
};

const del = (...paths) =>
  paths.forEach((p) => {
    try {
      if (p && fs.existsSync(p)) fs.unlinkSync(p);
    } catch (_) {}
  });

const cleanupUploads = (req) => {
  if (!req) return;
  if (req.file) del(req.file.path);
  if (!req.files) return;

  const entries = [
    'secretImage',
    'coverImage',
    'secret',
    'cover',
    'stego',
  ];

  for (const key of entries) {
    const files = req.files[key];
    if (Array.isArray(files)) {
      del(...files.map((file) => file.path));
    }
  }
};

// ── FIX: Reliable filename builder for decrypted outputs ─────────────────────
/**
 * Strips any encrypted-file suffixes and returns a clean base name.
 * Examples:
 *   "photo_encrypted.bin"       → "photo"
 *   "photo_encrypted_decrypted" → "photo"   (edge case from Python output path)
 *   "cover_stego.png"           → "cover_stego"
 *   "audio_encrypted.abin"      → "audio"
 *   "video_encrypted.vbin"      → "video"
 */
const cleanBaseName = (filename) =>
  path
    .basename(filename, path.extname(filename)) // strip extension
    .replace(/_encrypted(_decrypted)?$/, "") // strip _encrypted or _encrypted_decrypted
    .replace(/_decrypted$/, ""); // strip lone _decrypted

const extFromType = (type = "") =>
  ({
    "JPEG Image": ".jpg",
    "PNG Image": ".png",
    "GIF Image": ".gif",
    "PDF Document": ".pdf",
    "WAV Audio": ".wav",
    "MP3 Audio": ".mp3",
    "Text File": ".txt",
    GZIP: ".gz",
    "ZIP Archive": ".zip",
    "Binary Data": ".bin",
  })[type] || ".bin";

// ── Multer Configurations ─────────────────────────────────────────────────────
const imageMulter = multer({
  storage: multer.diskStorage({
    destination: (_, __, cb) => cb(null, uploadDir("original")),
    filename: (_, file, cb) => cb(null, `${Date.now()}-${file.originalname}`),
  }),
  limits: { fileSize: 1 * 1024 * 1024 * 1024 }, // 1 GB - supports large high-res images
});

const videoMulter = multer({
  storage: multer.diskStorage({
    destination: (_, __, cb) => cb(null, uploadDir("video")),
    filename: (_, file, cb) => cb(null, `${Date.now()}-${file.originalname}`),
  }),
  limits: { fileSize: 4 * 1024 * 1024 * 1024 }, // 4 GB - supports large videos
});

const audioMulter = multer({
  storage: multer.diskStorage({
    destination: (_, __, cb) => cb(null, uploadDir("audio")),
    filename: (_, file, cb) => cb(null, `${Date.now()}-${file.originalname}`),
  }),
  limits: { fileSize: 2 * 1024 * 1024 * 1024 }, // 2 GB - supports long audio recordings
});

const secretMulter = multer({
  storage: multer.diskStorage({
    destination: (_, __, cb) => cb(null, uploadDir("stego")),
    filename: (_, file, cb) =>
      cb(null, `${Date.now()}-secret-${file.originalname}`),
  }),
  limits: { fileSize: 2 * 1024 * 1024 * 1024 }, // 2 GB - supports large steganography operations
});

// ── Temp-file store ───────────────────────────────────────────────────────────
const tempExtracted = new Map();

// Purge expired entries every 5 minutes
setInterval(
  () => {
    const now = Date.now();
    for (const [id, item] of tempExtracted.entries()) {
      if (now > item.expires) {
        del(item.path);
        tempExtracted.delete(id);
      }
    }
  },
  5 * 60 * 1000,
);

// ─────────────────────────────────────────────────────────────────────────────
// 1. IMAGE ENCRYPTION
// ─────────────────────────────────────────────────────────────────────────────

router.post("/encrypt", imageMulter.single("image"), async (req, res) => {
  try {
    const { key, chaoticMap = "logistic" } = req.body;
    if (!req.file || !key)
      return res.status(400).json({ error: "Image and key required" });

    const result = await runPython(SCRIPTS.image, [
      "encrypt",
      req.file.path,
      key,
      chaoticMap,
    ]);
    if (!result.success) throw new Error(result.error);

    console.log(
      "🐍 Image encryption metrics received:",
      JSON.stringify(result.metrics, null, 2),
    );
    const cleanedMetrics = cleanMetrics(result.metrics);
    console.log(
      "✅ Cleaned metrics for DB:",
      JSON.stringify(cleanedMetrics, null, 2),
    );

    const doc = await new EncryptedImage({
      originalName: req.file.originalname,
      encryptedName: path.basename(result.encrypted_path),
      encryptedPath: result.encrypted_path,
      originalPath: req.file.path,
      size: req.file.size,
      mimeType: req.file.mimetype,
      mediaType: "image",
      chaoticMap,
      encryptionType: "basic",
      metrics: cleanedMetrics,
      status: "completed",
    }).save();

    console.log(
      "✅ Document saved with metrics:",
      JSON.stringify(doc.metrics, null, 2),
    );

    res.json({ success: true, fileId: doc._id, metrics: result.metrics });
  } catch (error) {
    res.status(500).json({ error: error.message });
  } finally {
    cleanupUploads(req);
  }
});

// ── FIX: Image Decrypt ────────────────────────────────────────────────────────
router.post("/decrypt", imageMulter.single("image"), async (req, res) => {
  try {
    const { key } = req.body;
    if (!req.file || !key)
      return res.status(400).json({ error: "File and key required" });

    const result = await runPython(SCRIPTS.image, [
      "decrypt",
      req.file.path,
      key,
    ]);
    if (!result.success) throw new Error(result.error);

    // ✅ FIX: Return the decrypted image blob directly, not a JSON URL
    const base = cleanBaseName(req.file.originalname);
    const filename = `decrypted_${base}.png`;

    // Send the decrypted image file directly as blob
    res.download(result.decrypted_path, filename, (err) => {
      if (!err) {
        // Clean up after successful download
        setTimeout(() => {
          del(result.decrypted_path);
        }, 5000);
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  } finally {
    if (req.file) del(req.file.path);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. IMAGE STEGANOGRAPHY
// ─────────────────────────────────────────────────────────────────────────────

router.post(
  "/encrypt-stego",
  secretMulter.fields([
    { name: "secretImage", maxCount: 1 },
    { name: "coverImage", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const { key, chaoticMap = "logistic" } = req.body;
      if (!req.files?.secretImage || !req.files?.coverImage || !key)
        return res.status(400).json({ error: "Missing required files or key" });

      const result = await runPython(SCRIPTS.stego, [
        "encrypt",
        req.files.secretImage[0].path,
        req.files.coverImage[0].path,
        key,
        chaoticMap,
      ]);
      if (!result.success) throw new Error(result.error);

      const doc = await new EncryptedImage({
        originalName: req.files.secretImage[0].originalname,
        encryptedName: path.basename(result.stego_path),
        encryptedPath: result.stego_path,
        size: req.files.secretImage[0].size,
        mimeType: "image/png",
        mediaType: "image",
        encryptionType: "steganography",
        chaoticMap,
        metrics: cleanMetrics(result.metrics),
        status: "completed",
      }).save();

      res.json({ success: true, fileId: doc._id, metrics: result.metrics });
    } catch (error) {
      res.status(500).json({ error: error.message });
    } finally {
      cleanupUploads(req);
    }
  },
);

// ── FIX: Image Stego Decrypt ──────────────────────────────────────────────────
router.post("/decrypt-stego", imageMulter.single("image"), async (req, res) => {
  try {
    const { key } = req.body;
    if (!req.file || !key)
      return res.status(400).json({ error: "File and key required" });

    const result = await runPython(SCRIPTS.stego, [
      "decrypt",
      req.file.path,
      key,
    ]);
    if (!result.success) throw new Error(result.error);

    // ✅ FIX: Return the extracted image blob directly, not a JSON URL
    const base = cleanBaseName(req.file.originalname);
    const filename = `extracted_${base}.png`;

    // Send the extracted image file directly as blob
    res.download(result.decrypted_path, filename, (err) => {
      if (!err) {
        // Clean up after successful download
        setTimeout(() => {
          del(result.decrypted_path);
        }, 5000);
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  } finally {
    if (req.file) del(req.file.path);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. VIDEO ENCRYPTION
// ─────────────────────────────────────────────────────────────────────────────

router.post("/encrypt-video", videoMulter.single("video"), async (req, res) => {
  try {
    const { key, chaoticMap = "logistic" } = req.body;
    if (!req.file || !key)
      return res.status(400).json({ error: "Video and key required" });

    const result = await runPython(SCRIPTS.video, [
      "encrypt",
      req.file.path,
      key,
      chaoticMap,
    ]);
    if (!result.success) throw new Error(result.error);

    const doc = await new EncryptedImage({
      originalName: req.file.originalname,
      encryptedName: path.basename(result.encrypted_path),
      encryptedPath: result.encrypted_path,
      size: req.file.size,
      mimeType: req.file.mimetype,
      mediaType: "video",
      chaoticMap,
      metrics: cleanMetrics(result.metrics),
      status: "completed",
    }).save();

    res.json({ success: true, fileId: doc._id, metrics: result.metrics });
  } catch (error) {
    res.status(500).json({ error: error.message });
  } finally {
    cleanupUploads(req);
  }
});

// ── FIX: Video Decrypt ────────────────────────────────────────────────────────
router.post("/decrypt-video", videoMulter.single("video"), async (req, res) => {
  try {
    const { key } = req.body;
    if (!req.file || !key)
      return res.status(400).json({ error: "File and key required" });

    const result = await runPython(SCRIPTS.video, [
      "decrypt",
      req.file.path,
      key,
    ]);
    if (!result.success) throw new Error(result.error);

    // ✅ FIX: Return the decrypted video blob directly, not a JSON URL
    const base = cleanBaseName(req.file.originalname);
    const filename = `decrypted_${base}.mp4`;

    // Send the decrypted video file directly as blob
    res.download(result.decrypted_path, filename, (err) => {
      if (!err) {
        // Clean up after successful download
        setTimeout(() => {
          del(result.decrypted_path);
        }, 10000);
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  } finally {
    if (req.file) del(req.file.path);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. AUDIO ENCRYPTION
// ─────────────────────────────────────────────────────────────────────────────

router.post("/encrypt-audio", audioMulter.single("audio"), async (req, res) => {
  try {
    const { key, chaoticMap = "logistic" } = req.body;
    if (!req.file || !key)
      return res.status(400).json({ error: "Audio and key required" });

    const result = await runPython(SCRIPTS.audio, [
      "encrypt",
      req.file.path,
      key,
      chaoticMap,
    ]);
    if (!result.success) throw new Error(result.error);

    const doc = await new EncryptedImage({
      originalName: req.file.originalname,
      encryptedName: path.basename(result.encrypted_path),
      encryptedPath: result.encrypted_path,
      size: req.file.size,
      mimeType: req.file.mimetype,
      mediaType: "audio",
      chaoticMap,
      metrics: cleanMetrics(result.metrics),
      status: "completed",
    }).save();

    res.json({ success: true, fileId: doc._id, metrics: result.metrics });
  } catch (error) {
    res.status(500).json({ error: error.message });
  } finally {
    cleanupUploads(req);
  }
});

// ── FIX: Audio Decrypt ────────────────────────────────────────────────────────
router.post("/decrypt-audio", audioMulter.single("audio"), async (req, res) => {
  try {
    const { key } = req.body;
    if (!req.file || !key)
      return res.status(400).json({ error: "File and key required" });

    const result = await runPython(SCRIPTS.audio, [
      "decrypt",
      req.file.path,
      key,
    ]);
    if (!result.success) throw new Error(result.error);

    // ✅ FIX: Return the decrypted audio with proper extension handling
    const base = cleanBaseName(req.file.originalname);

    // Check if file exists
    if (!fs.existsSync(result.decrypted_path)) {
      throw new Error(`Decrypted file not found: ${result.decrypted_path}`);
    }

    // Get actual file extension from path
    const actualExt = path.extname(result.decrypted_path);
    const filename = `decrypted_${base}${actualExt}`;

    // Send the decrypted audio file directly as blob with proper filename
    res.setHeader("X-Filename", filename);
    res.download(result.decrypted_path, filename, (err) => {
      if (!err) {
        // Clean up after successful download
        setTimeout(() => {
          del(result.decrypted_path);
        }, 5000);
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  } finally {
    if (req.file) del(req.file.path);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. AUDIO STEGANOGRAPHY
// ─────────────────────────────────────────────────────────────────────────────

router.post(
  "/steganography/audio/hide",
  secretMulter.fields([
    { name: "secret", maxCount: 1 },
    { name: "cover", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const { key, chaoticMap = "logistic" } = req.body;
      if (!req.files?.secret?.[0] || !req.files?.cover?.[0])
        return res
          .status(400)
          .json({ error: "Secret file and Cover audio required" });

      const outputPath = path.join(
        uploadDir("stego"),
        `stego_audio_${Date.now()}.wav`,
      );

      const result = await runPython(SCRIPTS.audioStego, [
        "hide",
        req.files.secret[0].path,
        req.files.cover[0].path,
        outputPath,
        key,
        chaoticMap,
      ]);
      if (!result.success) throw new Error(result.error);

      const doc = await new EncryptedImage({
        originalName: req.files.secret[0].originalname,
        encryptedName: path.basename(outputPath),
        encryptedPath: outputPath,
        size: req.files.secret[0].size,
        mimeType: req.files.cover[0].mimetype || "audio/wav",
        mediaType: "audio",
        encryptionType: "steganography",
        chaoticMap,
        metrics: cleanMetrics(result.metrics),
        status: "completed",
      }).save();

      res.json({ success: true, fileId: doc._id, metrics: result.metrics });
    } catch (e) {
      res.status(500).json({ error: e.message });
    } finally {
      cleanupUploads(req);
    }
  },
);

// ── FIX: Audio Stego Reveal ───────────────────────────────────────────────────
router.post(
  "/steganography/audio/reveal",
  audioMulter.single("stego"),
  async (req, res) => {
    try {
      const { key } = req.body;
      if (!req.file || !key)
        return res.status(400).json({ error: "Stego audio and key required" });

      const outputPath = path.join(
        uploadDir("decrypted"),
        `extracted_${Date.now()}`,
      );

      const result = await runPython(SCRIPTS.audioStego, [
        "reveal",
        req.file.path,
        outputPath,
        key,
      ]);
      if (!result.success) throw new Error(result.error);

      // ✅ FIX: use detected file type to assign correct extension
      const ext = extFromType(result.metrics?.file_type);
      const finalPath = outputPath + ext;
      if (fs.existsSync(outputPath)) fs.renameSync(outputPath, finalPath);

      // ✅ FIX: Return the extracted file blob directly, not a JSON URL
      const base = cleanBaseName(req.file.originalname);
      const filename = `extracted_${base}${ext}`;

      res.download(finalPath, filename, (err) => {
        if (!err) {
          // Clean up after successful download
          setTimeout(() => {
            del(finalPath);
          }, 5000);
        }
      });
    } catch (e) {
      res.status(500).json({ error: e.message });
    } finally {
      if (req.file) del(req.file.path);
    }
  },
);

// ─────────────────────────────────────────────────────────────────────────────
// 6. VIDEO STEGANOGRAPHY
// ─────────────────────────────────────────────────────────────────────────────

router.post(
  "/steganography/video/hide",
  secretMulter.fields([
    { name: "secret", maxCount: 1 },
    { name: "cover", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const { key, frameIndex = 0, chaoticMap = "logistic" } = req.body;
      if (!req.files?.secret?.[0] || !req.files?.cover?.[0])
        return res
          .status(400)
          .json({ error: "Secret file and Cover video required" });

      const outputPath = path.join(
        uploadDir("stego"),
        `stego_video_${Date.now()}.avi`,
      );

      const result = await runPython(SCRIPTS.videoStego, [
        "hide",
        req.files.secret[0].path,
        req.files.cover[0].path,
        outputPath,
        key,
        frameIndex,
        chaoticMap,
      ]);
      if (!result.success) throw new Error(result.error);

      const doc = await new EncryptedImage({
        originalName: req.files.secret[0].originalname,
        encryptedName: path.basename(outputPath),
        encryptedPath: outputPath,
        size: req.files.secret[0].size,
        mimeType: req.files.cover[0].mimetype || "video/avi",
        mediaType: "video",
        encryptionType: "steganography",
        chaoticMap,
        metrics: cleanMetrics(result.metrics),
        status: "completed",
      }).save();

      res.json({ success: true, fileId: doc._id, metrics: result.metrics });
    } catch (e) {
      res.status(500).json({ error: e.message });    } finally {
      cleanupUploads(req);    } finally {
      cleanupUploads(req);
    }
  },
);

// ── FIX: Video Stego Reveal ───────────────────────────────────────────────────
router.post(
  "/steganography/video/reveal",
  videoMulter.single("stego"),
  async (req, res) => {
    try {
      const { key, frameIndex = 0 } = req.body;
      if (!req.file || !key)
        return res.status(400).json({ error: "Stego video and key required" });

      const outputPath = path.join(
        uploadDir("decrypted"),
        `extracted_${Date.now()}`,
      );

      const result = await runPython(SCRIPTS.videoStego, [
        "reveal",
        req.file.path,
        outputPath,
        key,
        frameIndex,
      ]);
      if (!result.success) throw new Error(result.error);

      // ✅ FIX: use detected file type to assign correct extension
      const ext = extFromType(result.metrics?.file_type);
      const finalPath = outputPath + ext;
      if (fs.existsSync(outputPath)) fs.renameSync(outputPath, finalPath);

      // ✅ FIX: Return the extracted file blob directly, not a JSON URL
      const base = cleanBaseName(req.file.originalname);
      const filename = `extracted_${base}${ext}`;

      res.download(finalPath, filename, (err) => {
        if (!err) {
          // Clean up after successful download
          setTimeout(() => {
            del(finalPath);
          }, 10000);
        }
      });
    } catch (e) {
      res.status(500).json({ error: e.message });
    } finally {
      if (req.file) del(req.file.path);
    }
  },
);

// ─────────────────────────────────────────────────────────────────────────────
// SHARED UTILITY ROUTES
// ─────────────────────────────────────────────────────────────────────────────

/**
 * ✅ FIX: Download-temp no longer deletes the file inside res.download callback.
 * Instead it marks the entry as "downloaded" and a short delayed cleanup runs
 * after 60 s, so a second tap / browser retry still works.
 */
router.get("/download-temp/:tempId", (req, res) => {
  const item = tempExtracted.get(req.params.tempId);
  if (!item || Date.now() > item.expires) {
    tempExtracted.delete(req.params.tempId);
    return res.status(404).json({ error: "File expired or not found" });
  }

  res.download(item.path, item.filename, (err) => {
    if (err && !res.headersSent) {
      return res.status(500).json({ error: "Download failed" });
    }
    // Delay cleanup by 60 s to tolerate retries / browser pre-fetch
    setTimeout(() => {
      del(item.path);
      tempExtracted.delete(req.params.tempId);
    }, 60_000);
  });
});

router.get("/download/:id", async (req, res) => {
  try {
    const doc = await EncryptedImage.findById(req.params.id);
    if (!doc || !fs.existsSync(doc.encryptedPath))
      return res.status(404).json({ error: "File not found" });
    res.download(doc.encryptedPath, doc.encryptedName);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get("/images", async (req, res) => {
  try {
    const images = await EncryptedImage.find().sort({ uploadDate: -1 });
    res.json(images);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.delete("/images/:id", async (req, res) => {
  try {
    const doc = await EncryptedImage.findByIdAndDelete(req.params.id);
    if (doc) del(doc.encryptedPath, doc.originalPath);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
