-- Create the database if it doesn't exist
CREATE DATABASE IF NOT EXISTS Uniclub CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Select the database
USE Uniclub;

-- ========= CLUBS =========
-- Create clubs table first (if it doesn't exist)
CREATE TABLE IF NOT EXISTS clubs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(200),
  description TEXT,
  adviser VARCHAR(150),
  department VARCHAR(100),
  program JSON,
  status VARCHAR(50),
  category VARCHAR(100),
  photo VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ========= MESSAGES =========
CREATE TABLE IF NOT EXISTS messages (
  id INT AUTO_INCREMENT PRIMARY KEY,
  sender_name   VARCHAR(150) NOT NULL,
  sender_email  VARCHAR(150) NOT NULL,
  subject       VARCHAR(200) NOT NULL,
  content       TEXT NOT NULL,
  `read`        TINYINT(1) DEFAULT 0,
  created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ========= EVENTS =========
CREATE TABLE IF NOT EXISTS events (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(200) NOT NULL,
  club_id     INT,
  date        DATE,
  location    VARCHAR(200),
  description TEXT,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (club_id) REFERENCES clubs(id) ON DELETE SET NULL
);

-- ========= OFFICERS (used by routes joins) =========
-- Note: Run migrate_name_to_separate_fields.sql to convert from 'name' to 'first_name'/'last_name'
CREATE TABLE IF NOT EXISTS officers (
  id INT AUTO_INCREMENT PRIMARY KEY,
  first_name VARCHAR(100) NOT NULL,
  last_name  VARCHAR(100) NOT NULL,
  studentid  VARCHAR(50),
  club_id    INT,
  role       VARCHAR(100),
  department VARCHAR(100),
  program    VARCHAR(100),
  permissions JSON DEFAULT ('{}'),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (club_id) REFERENCES clubs(id) ON DELETE SET NULL
);

-- ========= REQUIREMENTS (as used by your admin routes) =========
-- (Different from the earlier "title/description" variant)
CREATE TABLE IF NOT EXISTS requirements (
  id INT AUTO_INCREMENT PRIMARY KEY,
  requirement TEXT NOT NULL,
  club_id     INT,
  due_date    DATE,
  status      VARCHAR(50),
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (club_id) REFERENCES clubs(id) ON DELETE SET NULL
);

-- ========= STUDENTS (counts + recent list) =========
-- Note: Run migrate_name_to_separate_fields.sql to convert from 'name' to 'first_name'/'last_name'
CREATE TABLE IF NOT EXISTS students (
  id INT AUTO_INCREMENT PRIMARY KEY,
  first_name  VARCHAR(100) NOT NULL,
  last_name   VARCHAR(100) NOT NULL,
  email       VARCHAR(150) UNIQUE,
  studentid   VARCHAR(50),
  password    VARCHAR(255),
  program     VARCHAR(100),
  year_level  VARCHAR(50),
  department  VARCHAR(100),
  birthdate   DATE,
  bio         TEXT,
  phone       VARCHAR(20),
  discord     VARCHAR(100),
  skills      JSON,
  interests   JSON,
  social_links JSON,
  profile_picture VARCHAR(255),
  location    VARCHAR(255),
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ========= ACTIVITIES (used on dashboard) =========
CREATE TABLE IF NOT EXISTS activities (
  id INT AUTO_INCREMENT PRIMARY KEY,
  activity  VARCHAR(200) NOT NULL,
  club      VARCHAR(200),
  date      DATE,
  location  VARCHAR(200),
  status    VARCHAR(50),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ========= ADMINS (for login) =========
CREATE TABLE IF NOT EXISTS admins (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(100) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ========= STUDENT POINTS (points system) =========
CREATE TABLE IF NOT EXISTS student_points (
  id INT AUTO_INCREMENT PRIMARY KEY,
  student_id INT NOT NULL,
  points INT NOT NULL DEFAULT 0,
  source VARCHAR(100) NOT NULL,
  description TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
  INDEX idx_student_id (student_id),
  INDEX idx_created_at (created_at)
);
