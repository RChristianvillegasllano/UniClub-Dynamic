-- ========= CLUBS =========
-- Add 'adviser' column if it doesn't exist
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_name = 'clubs' AND column_name = 'adviser'
  ) THEN
    ALTER TABLE clubs ADD COLUMN adviser VARCHAR(150);
  END IF;
END$$;

-- Also ensure optional columns used by routes exist
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='clubs' AND column_name='department') THEN
    ALTER TABLE clubs ADD COLUMN department VARCHAR(100);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='clubs' AND column_name='program') THEN
    ALTER TABLE clubs ADD COLUMN program VARCHAR(100);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='clubs' AND column_name='status') THEN
    ALTER TABLE clubs ADD COLUMN status VARCHAR(50);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='clubs' AND column_name='created_at') THEN
    ALTER TABLE clubs ADD COLUMN created_at TIMESTAMP DEFAULT NOW();
  END IF;
END$$;

-- ========= MESSAGES =========
CREATE TABLE IF NOT EXISTS messages (
  id SERIAL PRIMARY KEY,
  sender_name   VARCHAR(150) NOT NULL,
  sender_email  VARCHAR(150) NOT NULL,
  subject       VARCHAR(200) NOT NULL,
  content       TEXT NOT NULL,
  read          BOOLEAN DEFAULT FALSE,
  created_at    TIMESTAMP DEFAULT NOW()
);

-- ========= EVENTS =========
CREATE TABLE IF NOT EXISTS events (
  id SERIAL PRIMARY KEY,
  name        VARCHAR(200) NOT NULL,
  club_id     INTEGER REFERENCES clubs(id) ON DELETE SET NULL,
  date        DATE,
  location    VARCHAR(200),
  description TEXT,
  created_at  TIMESTAMP DEFAULT NOW()
);

-- ========= OFFICERS (used by routes joins) =========
CREATE TABLE IF NOT EXISTS officers (
  id SERIAL PRIMARY KEY,
  name       VARCHAR(150) NOT NULL,
  studentid  VARCHAR(50),
  club_id    INTEGER REFERENCES clubs(id) ON DELETE SET NULL,
  role       VARCHAR(100),
  department VARCHAR(100),
  program    VARCHAR(100),
  created_at TIMESTAMP DEFAULT NOW()
);

-- ========= REQUIREMENTS (as used by your admin routes) =========
-- (Different from the earlier "title/description" variant)
CREATE TABLE IF NOT EXISTS requirements (
  id SERIAL PRIMARY KEY,
  requirement TEXT NOT NULL,
  club_id     INTEGER REFERENCES clubs(id) ON DELETE SET NULL,
  due_date    DATE,
  status      VARCHAR(50),
  created_at  TIMESTAMP DEFAULT NOW()
);

-- ========= STUDENTS (counts + recent list) =========
CREATE TABLE IF NOT EXISTS students (
  id SERIAL PRIMARY KEY,
  name        VARCHAR(150) NOT NULL,
  email       VARCHAR(150) UNIQUE,
  program     VARCHAR(100),
  year_level  VARCHAR(50),
  created_at  TIMESTAMP DEFAULT NOW()
);

-- ========= ACTIVITIES (used on dashboard) =========
CREATE TABLE IF NOT EXISTS activities (
  id SERIAL PRIMARY KEY,
  activity  VARCHAR(200) NOT NULL,
  club      VARCHAR(200),
  date      DATE,
  location  VARCHAR(200),
  status    VARCHAR(50),
  created_at TIMESTAMP DEFAULT NOW()
);

-- ========= ADMINS (for login) =========
CREATE TABLE IF NOT EXISTS admins (
  id SERIAL PRIMARY KEY,
  username VARCHAR(100) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);
  