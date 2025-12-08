-- ============================================================
-- Migration: Add Profile Columns to Students Table
-- Purpose: Add profile-related columns (bio, phone, discord, skills, 
--          interests, social_links, profile_picture, location) to 
--          the students table for the profile page functionality
-- 
-- Usage: Run this script to add profile columns to existing databases.
--        For new databases, the columns are already in Uniclub.sql
-- ============================================================

USE Uniclub;

-- Function to safely add a column (checks if it exists first)
-- Note: Run each ALTER TABLE statement individually.
--       If you get "Duplicate column name" error, that column already exists - skip it.

-- Add bio column (TEXT for longer descriptions)
SET @dbname = DATABASE();
SET @tablename = "students";
SET @columnname = "bio";
SET @preparedStatement = (SELECT IF(
  (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE
      (table_name = @tablename)
      AND (table_schema = @dbname)
      AND (column_name = @columnname)
  ) > 0,
  "SELECT 'Column bio already exists.';",
  "ALTER TABLE students ADD COLUMN bio TEXT;"
));
PREPARE alterIfNotExists FROM @preparedStatement;
EXECUTE alterIfNotExists;
DEALLOCATE PREPARE alterIfNotExists;

-- Add phone column
SET @columnname = "phone";
SET @preparedStatement = (SELECT IF(
  (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE
      (table_name = @tablename)
      AND (table_schema = @dbname)
      AND (column_name = @columnname)
  ) > 0,
  "SELECT 'Column phone already exists.';",
  "ALTER TABLE students ADD COLUMN phone VARCHAR(20);"
));
PREPARE alterIfNotExists FROM @preparedStatement;
EXECUTE alterIfNotExists;
DEALLOCATE PREPARE alterIfNotExists;

-- Add discord column
SET @columnname = "discord";
SET @preparedStatement = (SELECT IF(
  (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE
      (table_name = @tablename)
      AND (table_schema = @dbname)
      AND (column_name = @columnname)
  ) > 0,
  "SELECT 'Column discord already exists.';",
  "ALTER TABLE students ADD COLUMN discord VARCHAR(100);"
));
PREPARE alterIfNotExists FROM @preparedStatement;
EXECUTE alterIfNotExists;
DEALLOCATE PREPARE alterIfNotExists;

-- Add skills column
SET @columnname = "skills";
SET @preparedStatement = (SELECT IF(
  (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE
      (table_name = @tablename)
      AND (table_schema = @dbname)
      AND (column_name = @columnname)
  ) > 0,
  "SELECT 'Column skills already exists.';",
  "ALTER TABLE students ADD COLUMN skills JSON;"
));
PREPARE alterIfNotExists FROM @preparedStatement;
EXECUTE alterIfNotExists;
DEALLOCATE PREPARE alterIfNotExists;

-- Add interests column
SET @columnname = "interests";
SET @preparedStatement = (SELECT IF(
  (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE
      (table_name = @tablename)
      AND (table_schema = @dbname)
      AND (column_name = @columnname)
  ) > 0,
  "SELECT 'Column interests already exists.';",
  "ALTER TABLE students ADD COLUMN interests JSON;"
));
PREPARE alterIfNotExists FROM @preparedStatement;
EXECUTE alterIfNotExists;
DEALLOCATE PREPARE alterIfNotExists;

-- Add social_links column
SET @columnname = "social_links";
SET @preparedStatement = (SELECT IF(
  (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE
      (table_name = @tablename)
      AND (table_schema = @dbname)
      AND (column_name = @columnname)
  ) > 0,
  "SELECT 'Column social_links already exists.';",
  "ALTER TABLE students ADD COLUMN social_links JSON;"
));
PREPARE alterIfNotExists FROM @preparedStatement;
EXECUTE alterIfNotExists;
DEALLOCATE PREPARE alterIfNotExists;

-- Add profile_picture column
SET @columnname = "profile_picture";
SET @preparedStatement = (SELECT IF(
  (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE
      (table_name = @tablename)
      AND (table_schema = @dbname)
      AND (column_name = @columnname)
  ) > 0,
  "SELECT 'Column profile_picture already exists.';",
  "ALTER TABLE students ADD COLUMN profile_picture VARCHAR(255);"
));
PREPARE alterIfNotExists FROM @preparedStatement;
EXECUTE alterIfNotExists;
DEALLOCATE PREPARE alterIfNotExists;

-- Add location column
SET @columnname = "location";
SET @preparedStatement = (SELECT IF(
  (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE
      (table_name = @tablename)
      AND (table_schema = @dbname)
      AND (column_name = @columnname)
  ) > 0,
  "SELECT 'Column location already exists.';",
  "ALTER TABLE students ADD COLUMN location VARCHAR(255);"
));
PREPARE alterIfNotExists FROM @preparedStatement;
EXECUTE alterIfNotExists;
DEALLOCATE PREPARE alterIfNotExists;

-- ============================================================
-- Verification queries (run these to check the migration)
-- ============================================================
-- SELECT column_name, data_type, character_maximum_length, is_nullable
-- FROM information_schema.columns
-- WHERE table_name = 'students' AND table_schema = 'Uniclub'
-- ORDER BY ordinal_position;

