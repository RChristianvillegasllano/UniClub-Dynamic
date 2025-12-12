-- ============================================================
-- Migration: Create event_attendance table
-- Purpose: Track student RSVP/attendance for events
-- ============================================================

USE Uniclub;

-- Create event_attendance table to track student event RSVPs
CREATE TABLE IF NOT EXISTS event_attendance (
  id INT AUTO_INCREMENT PRIMARY KEY,
  event_id INT NOT NULL,
  student_id INT NOT NULL,
  status VARCHAR(50) DEFAULT 'going', -- 'going' or 'interested'
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE,
  FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
  UNIQUE KEY unique_event_student (event_id, student_id),
  INDEX idx_event_id (event_id),
  INDEX idx_student_id (student_id)
);

-- ============================================================
-- Verification query (run this to check the migration)
-- ============================================================
-- SELECT table_name, column_name, data_type, is_nullable
-- FROM information_schema.columns
-- WHERE table_schema = 'Uniclub' AND table_name = 'event_attendance'
-- ORDER BY ordinal_position;








