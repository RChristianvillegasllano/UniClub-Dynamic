-- ============================================================
-- Migration: Split 'name' column into 'first_name' and 'last_name'
-- For: officers and students tables
-- ============================================================

-- ========= OFFICERS TABLE =========
-- Step 1: Add new columns
ALTER TABLE officers 
  ADD COLUMN IF NOT EXISTS first_name VARCHAR(100),
  ADD COLUMN IF NOT EXISTS last_name VARCHAR(100);

-- Step 2: Migrate existing data from 'name' to 'first_name' and 'last_name'
-- This splits the name on the last space (handles middle names by putting them in first_name)
-- For names like "John Michael Smith", it will be: first_name="John Michael", last_name="Smith"
UPDATE officers
SET 
  first_name = TRIM(
    CASE 
      WHEN name IS NULL OR TRIM(name) = '' THEN ''
      WHEN position(' ' IN TRIM(name)) = 0 THEN TRIM(name)  -- No space, use entire name as first_name
      ELSE array_to_string((string_to_array(TRIM(name), ' '))[1:array_length(string_to_array(TRIM(name), ' '), 1) - 1], ' ')
    END
  ),
  last_name = TRIM(
    CASE 
      WHEN name IS NULL OR TRIM(name) = '' THEN ''
      WHEN position(' ' IN TRIM(name)) = 0 THEN ''  -- No space, no last name
      ELSE (string_to_array(TRIM(name), ' '))[array_length(string_to_array(TRIM(name), ' '), 1)]
    END
  )
WHERE first_name IS NULL OR last_name IS NULL;

-- Step 3: Make first_name and last_name NOT NULL (after migration)
-- First, handle any NULL values
UPDATE officers SET first_name = COALESCE(first_name, '') WHERE first_name IS NULL;
UPDATE officers SET last_name = COALESCE(last_name, '') WHERE last_name IS NULL;

-- Step 4: Add NOT NULL constraints
ALTER TABLE officers 
  ALTER COLUMN first_name SET NOT NULL,
  ALTER COLUMN last_name SET NOT NULL;

-- Step 5: Drop the old 'name' column
ALTER TABLE officers DROP COLUMN IF EXISTS name;

-- ========= STUDENTS TABLE =========
-- Step 1: Add new columns
ALTER TABLE students 
  ADD COLUMN IF NOT EXISTS first_name VARCHAR(100),
  ADD COLUMN IF NOT EXISTS last_name VARCHAR(100);

-- Step 2: Migrate existing data from 'name' to 'first_name' and 'last_name'
-- This splits the name on the last space (handles middle names by putting them in first_name)
-- For names like "John Michael Smith", it will be: first_name="John Michael", last_name="Smith"
UPDATE students
SET 
  first_name = TRIM(
    CASE 
      WHEN name IS NULL OR TRIM(name) = '' THEN ''
      WHEN position(' ' IN TRIM(name)) = 0 THEN TRIM(name)  -- No space, use entire name as first_name
      ELSE array_to_string((string_to_array(TRIM(name), ' '))[1:array_length(string_to_array(TRIM(name), ' '), 1) - 1], ' ')
    END
  ),
  last_name = TRIM(
    CASE 
      WHEN name IS NULL OR TRIM(name) = '' THEN ''
      WHEN position(' ' IN TRIM(name)) = 0 THEN ''  -- No space, no last name
      ELSE (string_to_array(TRIM(name), ' '))[array_length(string_to_array(TRIM(name), ' '), 1)]
    END
  )
WHERE first_name IS NULL OR last_name IS NULL;

-- Step 3: Make first_name and last_name NOT NULL (after migration)
-- First, handle any NULL values
UPDATE students SET first_name = COALESCE(first_name, '') WHERE first_name IS NULL;
UPDATE students SET last_name = COALESCE(last_name, '') WHERE last_name IS NULL;

-- Step 4: Add NOT NULL constraints
ALTER TABLE students 
  ALTER COLUMN first_name SET NOT NULL,
  ALTER COLUMN last_name SET NOT NULL;

-- Step 5: Drop the old 'name' column
ALTER TABLE students DROP COLUMN IF EXISTS name;

-- ============================================================
-- Verification queries (run these to check the migration)
-- ============================================================
-- SELECT id, first_name, last_name, studentid FROM officers ORDER BY last_name, first_name LIMIT 10;
-- SELECT id, first_name, last_name, email FROM students ORDER BY last_name, first_name LIMIT 10;

