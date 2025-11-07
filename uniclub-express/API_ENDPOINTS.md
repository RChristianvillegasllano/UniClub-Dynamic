# UniClub API Endpoints

This document describes the REST API endpoints available at `/api` for faster data loading and fetching.

## Authentication

Most endpoints require admin authentication via session. Public endpoints (clubs, events, officers, requirements) can be accessed without authentication for read operations.

## Base URL

All endpoints are prefixed with `/api`

## Endpoints

### Dashboard

- **GET** `/api/dashboard` - Get dashboard statistics and recent data
  - Returns: counts, recent students, clubs, officers, activities, requirements, messages, analytics
  - Requires: Admin authentication

### Students

- **GET** `/api/students` - Get all students (paginated)
  - Query params: `page`, `limit`, `search`
  - Requires: Admin authentication

- **GET** `/api/students/:id` - Get single student
  - Requires: Admin authentication

- **POST** `/api/students` - Create new student
  - Body: `{ name, studentid, email, department, program, year }`
  - Requires: Admin authentication

- **PUT** `/api/students/:id` - Update student
  - Body: `{ name, studentid, email, department, program, year }`
  - Requires: Admin authentication

- **DELETE** `/api/students/:id` - Delete student
  - Requires: Admin authentication

### Clubs

- **GET** `/api/clubs` - Get all clubs (paginated)
  - Query params: `page`, `limit`, `search`
  - Public endpoint

- **GET** `/api/clubs/:id` - Get single club
  - Public endpoint

- **POST** `/api/clubs` - Create new club
  - Body: `{ name, description, adviser, department }`
  - Requires: Admin authentication

- **PUT** `/api/clubs/:id` - Update club
  - Body: `{ name, description, adviser, department }`
  - Requires: Admin authentication

- **DELETE** `/api/clubs/:id` - Delete club
  - Requires: Admin authentication

### Officers

- **GET** `/api/officers` - Get all officers (paginated)
  - Query params: `page`, `limit`, `search`, `club_id`
  - Public endpoint (read-only)

- **GET** `/api/officers/:id` - Get single officer
  - Public endpoint

- **POST** `/api/officers` - Create new officer
  - Body: `{ name, studentid, club_id, role, department, program, permissions }`
  - Requires: Admin authentication

- **PUT** `/api/officers/:id` - Update officer
  - Body: `{ name, studentid, club_id, role, department, program, permissions }`
  - Requires: Admin authentication

- **DELETE** `/api/officers/:id` - Delete officer
  - Requires: Admin authentication

### Events

- **GET** `/api/events` - Get all events (paginated)
  - Query params: `page`, `limit`, `search`, `status`
  - Public endpoint

- **GET** `/api/events/:id` - Get single event
  - Public endpoint

- **POST** `/api/events` - Create new event
  - Body: `{ name, club, date, location, description, status }`
  - Requires: Admin authentication

- **PUT** `/api/events/:id` - Update event
  - Body: `{ name, club, date, location, description, status }`
  - Requires: Admin authentication

- **DELETE** `/api/events/:id` - Delete event
  - Requires: Admin authentication

### Requirements

- **GET** `/api/requirements` - Get all requirements (paginated)
  - Query params: `page`, `limit`, `search`, `status`
  - Public endpoint

- **GET** `/api/requirements/:id` - Get single requirement
  - Public endpoint

- **POST** `/api/requirements` - Create new requirement
  - Body: `{ requirement, club_id, due_date, status }`
  - Requires: Admin authentication

- **PUT** `/api/requirements/:id` - Update requirement
  - Body: `{ requirement, club_id, due_date, status }`
  - Requires: Admin authentication

- **DELETE** `/api/requirements/:id` - Delete requirement
  - Requires: Admin authentication

### Messages

- **GET** `/api/messages` - Get all messages (paginated)
  - Query params: `page`, `limit`, `read` (true/false)
  - Requires: Admin authentication

- **GET** `/api/messages/:id` - Get single message (marks as read)
  - Requires: Admin authentication

- **DELETE** `/api/messages/:id` - Delete message
  - Requires: Admin authentication

## Response Format

All endpoints return JSON in the following format:

### Success Response
```json
{
  "success": true,
  "data": [...],
  "pagination": {
    "page": 1,
    "limit": 50,
    "total": 100,
    "totalPages": 2
  }
}
```

### Error Response
```json
{
  "success": false,
  "error": "Error message"
}
```

## Performance Features

1. **Caching**: Public read endpoints include cache headers (30-120 seconds)
2. **Pagination**: All list endpoints support pagination
3. **Search**: Most endpoints support search/filtering
4. **Parallel Queries**: Dashboard endpoint uses parallel database queries
5. **Optimized Queries**: Efficient SQL with proper joins and indexing

## Usage Example

```javascript
// Fetch dashboard data
fetch('/api/dashboard')
  .then(res => res.json())
  .then(data => console.log(data));

// Fetch clubs with pagination
fetch('/api/clubs?page=1&limit=10&search=tech')
  .then(res => res.json())
  .then(data => console.log(data.data));

// Create a new club
fetch('/api/clubs', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include', // Include session cookie
  body: JSON.stringify({
    name: 'Tech Club',
    description: 'Technology enthusiasts',
    adviser: 'Dr. Smith',
    department: 'Computer Science'
  })
})
  .then(res => res.json())
  .then(data => console.log(data));
```


