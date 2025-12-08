-- Migration: Add photo column to clubs table
-- Run this if your clubs table already exists and doesn't have the photo column

USE Uniclub;

-- Add photo column to clubs table if it doesn't exist
ALTER TABLE clubs 
ADD COLUMN IF NOT EXISTS photo VARCHAR(255) NULL 
AFTER category;

-- Note: If your MySQL version doesn't support IF NOT EXISTS, use this instead:
-- ALTER TABLE clubs ADD COLUMN photo VARCHAR(255) NULL AFTER category;







