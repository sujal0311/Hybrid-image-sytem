const mongoose = require('mongoose');

const encryptedImageSchema = new mongoose.Schema({
  // Basic Information
  originalName: {
    type: String,
    required: true,
    trim: true
  },
  encryptedName: {
    type: String,
    required: true,  // ✅ This MUST be provided
    trim: true
  },
  encryptedPath: {
    type: String,
    required: true
  },
  originalPath: {
    type: String,
    default: null
  },
  size: {
    type: Number,
    required: true,
    min: 0
  },
  mimeType: {
    type: String,
    required: true
  },
  
  // Encryption Configuration
  chaoticMap: {
    type: String,
    enum: ['logistic', 'arnold', 'tent', 'henon'],
    default: 'logistic'
  },
  encryptionType: {
    type: String,
    enum: ['basic', 'steganography'],
    default: 'basic'
  },
  
  // Dates
  uploadDate: {
    type: Date,
    default: Date.now
  },
  
  // Metrics
  metrics: {
    encryptionTime: {
      type: Number,
      default: 0
    },
    entropy: {
      original: {
        type: Number,
        default: 0
      },
      encrypted: {
        type: Number,
        default: 0
      }
    },
    npcr: {
      type: Number,
      default: 0
    },
    uaci: {
      type: Number,
      default: 0
    }
  },
  
  // Status
  status: {
    type: String,
    enum: ['pending', 'processing', 'completed', 'failed'],
    default: 'completed'
  }
}, {
  timestamps: true
});

// Indexes
encryptedImageSchema.index({ uploadDate: -1 });
encryptedImageSchema.index({ chaoticMap: 1 });

module.exports = mongoose.model('EncryptedImage', encryptedImageSchema);
