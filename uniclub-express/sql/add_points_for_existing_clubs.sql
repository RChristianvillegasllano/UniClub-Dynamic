-- Migration script to award points retroactively for existing approved club memberships
-- This script awards 5 points to students who have already joined clubs

USE Uniclub;

-- Create student_points table if it doesn't exist
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

-- Award 5 points to all students who have approved club memberships
-- Only award points if they haven't been awarded for this specific club membership
INSERT INTO student_points (student_id, points, source, description, created_at)
SELECT 
  ma.student_id,
  5 as points,
  'club_join' as source,
  CONCAT('Joined ', COALESCE(c.name, 'Club'), ' (retroactive - application_id:', ma.id, ')') as description,
  ma.created_at
FROM membership_applications ma
LEFT JOIN clubs c ON c.id = ma.club_id
WHERE LOWER(COALESCE(ma.status, '')) = 'approved'
  AND ma.student_id IS NOT NULL
  AND NOT EXISTS (
    -- Check if points were already awarded for this application
    SELECT 1 
    FROM student_points sp 
    WHERE sp.student_id = ma.student_id 
      AND sp.source = 'club_join'
      AND sp.description LIKE CONCAT('%application_id:', ma.id, '%')
  )
ON DUPLICATE KEY UPDATE id = id; -- Prevent duplicates if script is run multiple times

-- Show summary
SELECT 
  COUNT(*) as total_points_awarded,
  COUNT(DISTINCT student_id) as students_awarded,
  SUM(points) as total_points
FROM student_points
WHERE source = 'club_join';







