import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Ensure uploads directory exists
const clubUploadsDir = path.join(__dirname, '../public/img/clubs');
if (!fs.existsSync(clubUploadsDir)) {
  fs.mkdirSync(clubUploadsDir, { recursive: true });
}

const studentUploadsDir = path.join(__dirname, '../public/img/students');
if (!fs.existsSync(studentUploadsDir)) {
  fs.mkdirSync(studentUploadsDir, { recursive: true });
}

const eventDocumentsDir = path.join(__dirname, '../public/uploads/events');
if (!fs.existsSync(eventDocumentsDir)) {
  fs.mkdirSync(eventDocumentsDir, { recursive: true });
}

// Configure storage
const clubStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, clubUploadsDir);
  },
  filename: function (req, file, cb) {
    // Generate unique filename: club-{timestamp}-{random}.{ext}
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, `club-${uniqueSuffix}${ext}`);
  }
});

// File filter - only images
const fileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|gif|webp/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype);

  if (mimetype && extname) {
    return cb(null, true);
  } else {
    cb(new Error('Only image files are allowed (jpeg, jpg, png, gif, webp)'));
  }
};

const studentStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, studentUploadsDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, `student-${uniqueSuffix}${ext}`);
  }
});

// Configure multer
export const uploadClubPhoto = multer({
  storage: clubStorage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  },
  fileFilter: fileFilter
});

export const uploadStudentPhoto = multer({
  storage: studentStorage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  },
  fileFilter: fileFilter
});

// Event documents storage (PDF, DOC, DOCX, etc.)
const eventDocumentsStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, eventDocumentsDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, `event-doc-${uniqueSuffix}${ext}`);
  }
});

// File filter for event documents - allow PDF, DOC, DOCX, TXT, etc.
const eventDocumentsFilter = (req, file, cb) => {
  const allowedTypes = /pdf|doc|docx|txt|rtf|odt/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = file.mimetype === 'application/pdf' || 
                   file.mimetype === 'application/msword' ||
                   file.mimetype === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' ||
                   file.mimetype === 'text/plain' ||
                   file.mimetype === 'application/rtf' ||
                   file.mimetype === 'application/vnd.oasis.opendocument.text';

  if (mimetype && extname) {
    return cb(null, true);
  } else {
    cb(new Error('Only document files are allowed (PDF, DOC, DOCX, TXT, RTF, ODT)'));
  }
};

// Configure multer for event documents (3 files: activity_proposal, letter_of_intent, budgetary_requirement)
export const uploadEventDocuments = multer({
  storage: eventDocumentsStorage,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit per file
  },
  fileFilter: eventDocumentsFilter
}).fields([
  { name: 'activity_proposal', maxCount: 1 },
  { name: 'letter_of_intent', maxCount: 1 },
  { name: 'budgetary_requirement', maxCount: 1 }
]);






