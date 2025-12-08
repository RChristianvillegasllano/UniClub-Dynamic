-- ============================================================
-- Migration: Add Signup Form Fields to Students Table
-- Purpose: Add birthdate, studentid, department, and password columns
--          to match the student signup form requirements
-- ============================================================

-- Add birthdate column (DATE type for date of birth)
ALTER TABLE students 
ADD COLUMN IF NOT EXISTS birthdate DATE;

-- Add studentid column (VARCHAR(50) to store 6-digit student ID)
ALTER TABLE students 
ADD COLUMN IF NOT EXISTS studentid VARCHAR(50);

-- Add department column (VARCHAR(100) to store department name)
ALTER TABLE students 
ADD COLUMN IF NOT EXISTS department VARCHAR(100);

-- Add password column (VARCHAR(255) to store hashed password for authentication)
ALTER TABLE students 
ADD COLUMN IF NOT EXISTS password VARCHAR(255);

-- Optional: Add unique constraint on studentid if you want to ensure each student ID is unique
-- Uncomment the following lines if you want to enforce unique student IDs:
-- ALTER TABLE students 
-- ADD CONSTRAINT unique_studentid UNIQUE (studentid);

-- Add index on studentid for faster lookups
CREATE INDEX IF NOT EXISTS idx_students_studentid ON students(studentid);

-- Add index on email for faster lookups (if not already exists)
CREATE INDEX IF NOT EXISTS idx_students_email ON students(email);

-- ============================================================
-- Verification queries (run these to check the migration)
-- ============================================================
-- SELECT column_name, data_type, character_maximum_length, is_nullable
-- FROM information_schema.columns
-- WHERE table_name = 'students'
-- ORDER BY ordinal_position;











