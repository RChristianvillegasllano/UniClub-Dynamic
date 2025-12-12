# Tier Permissions System

This document describes the hierarchical permission system for club officers in the UniClub Management System.

## Overview

The permission system is organized into **4 main tiers**, with Tier 3 having 6 sub-categories (3A-3F) for specialized roles. Each tier has distinct permissions and dashboard visibility.

---

## 🟥 TIER 1 – EXECUTIVE LEVEL (FULL POWER)

### Roles
- **President**
- **Supremo** / **Grand Peer** / **Head** / **Adviser** / **Chairperson** (Highest Role Equivalent)

All counted as President-tier.

### Permissions

**Full CRUD on:**
- Clubs
- Officers
- Events
- Finance
- Attendance
- Documents

**Special Powers:**
- Approve/Reject officer accounts
- Override VP decisions
- Publish announcements
- Create executive reports
- Access system settings
- Access activity logs

### Dashboard Visibility
- **All pages visible**

---

## 🟧 TIER 2 – MANAGEMENT LEVEL (Vice Presidents + High Officers)

### Roles
All of the following belong here (same level of power):

- Vice-President Internal
- Vice-President External
- Executive VP
- VP Finance
- VP Logistics
- VP Production
- VP Creatives
- VP Promotion & Communication
- VP Religious / VP Social
- Internal & External VP (Red Cross / Peer Facilitators)
- Interyor Heneral
- Heneral Pangkayapaan
- Punong Konsehal
- 1st–4th Konsehal
- Kalihim Heneral
- Heneral Pampinansyal
- Heneral Pangkomunikasyon

### Permissions

**Manage:**
- Announcements (Create + Update + Delete, but **PUBLISH requires President**)
- Events (CRUD)
- Committees (CRUD)
- Member list (CRUD)
- Attendance (CRUD)
- Inventory / Logistics Modules

**View Only:**
- Finance
- Logs

**Restrictions:**
- Cannot approve officer accounts
- Cannot change system settings

### Dashboard Visibility
- Announcements
- Events
- Committees
- Members
- Attendance
- Inventory
- Reports
- Finance (read only)

---

## 🟡 TIER 3 – MID-LEVEL (UNIQUE PER ROLE)

**Important:** Tier 3 is **NOT equal power**. Each officer has distinct permissions depending on the nature of their job.

### TIER 3A — Documentation Roles

#### Roles
1. Secretary
2. Organizational Secretary
3. Corresponding Secretary
4. Recording Secretary

#### Permissions
- CRUD meeting minutes
- CRUD internal documents
- Upload requirements/forms
- Record attendance remarks (create only)
- View events & members

#### Dashboard
- Meeting Minutes
- Documents
- Events (view only)
- Members (view only)

---

### TIER 3B — Finance Roles

#### Treasurer Roles
1. Treasurer
2. Executive Treasurer
3. Assistant Treasurer
4. Finance & Accounting
5. Business & Finance Officer
6. Financial Officers

#### Treasurer Permissions
- Full finance CRUD
- Upload receipts
- Track income & expenses
- Generate financial statements

#### Treasurer Dashboard
- Finance
- Expense Reports
- Members (view)
- Events (view)

---

#### Auditor Roles
1. Auditor
2. Peer Auditor
3. Assistant Auditor

#### Auditor Permissions
- View + comment on finance
- Approve/validate treasurer reports
- Generate audit findings

#### Auditor Dashboard
- Audit Logs
- Finance (view/comment only)
- Members (view)
- Events (view)

---

### TIER 3C — Public Relations Roles

#### Roles
1. PIO
2. PRO
3. Public Relations Officer
4. Public Information Officer (1 & 2)

#### Permissions
- Create announcement drafts
- Create publicity write-ups
- Upload posters
- **Cannot publish announcements** (President only)

#### Dashboard
- Announcement Drafts
- Events (view only)

---

### TIER 3D — Logistics, Production, and Technical Roles

#### Roles
1. Logistics Officer
2. VP Logistics
3. Event Logistics
4. Production
5. Stage & Decor Leads
6. Tech Lead
7. Audio-Visual
8. Multimedia
9. Creatives
10. Business Manager

#### Permissions
- Manage equipment inventory (CRUD)
- Handle production materials
- Upload event requirements
- Assist organizers

#### Dashboard
- Inventory
- Event Materials
- Events (view only)

---

### TIER 3E — Year-Level Representatives

#### Roles
1. 1st Year to 4th Year Representatives (all clubs)

#### Permissions
- Validate attendance (Create only)
- Submit reports to VP/President
- **Cannot edit events or finances**

#### Dashboard
- Events (view only)
- Attendance (view only)
- Submissions Page

---

### TIER 3F — Committee Heads

#### Example Roles
- Shepherding
- Outreach
- Social Affairs
- Religious Affairs
- Community Extension Coordinator
- Committee (Red Cross)

#### Permissions
- Manage committee tasks (CRUD)
- Submit reports
- View events

#### Dashboard
- Committee Page
- Events (view only)
- Submissions

---

## 🟩 TIER 4 – ENTRY LEVEL / GENERAL MEMBERS

### Roles
(All clubs have Members, Volunteers, or Non-officer accounts)

### Permissions
- View announcements
- View events
- Submit attendance
- Submit forms

### Dashboard
- Home
- Events
- Announcements

---

## 📌 FINAL MERGED ROLE LIST (FOR DB)

### Tier 1
- President
- Supremo / Grand Peer / Chief Executive Equivalent

### Tier 2
- ALL Vice Presidents
- All "Heneral" positions
- Punong/Konsehal and similar roles

### Tier 3 – Unique Roles
- Secretaries
- Treasurers
- Auditors
- Public Relations Officers
- Logistics/Tech/Production
- Business Managers
- Committee Heads
- Year Representatives

### Tier 4
- Members
- Volunteers
- Non-officer accounts

---

## Implementation

The tier permissions system is implemented in `config/tierPermissions.js` and provides the following functions:

- `getTierForRole(role)` - Get tier level for a role
- `getPermissionsForRole(role)` - Get all permissions for a role
- `getDashboardPagesForRole(role)` - Get dashboard pages for a role
- `hasPermission(role, permission)` - Check if role has specific permission
- `canAccessPage(role, page)` - Check if role can access a dashboard page
- `getRoleInfo(role)` - Get comprehensive role information

### Usage Example

```javascript
import { getPermissionsForRole, hasPermission, canAccessPage } from './config/tierPermissions.js';

// Get permissions for a role
const permissions = getPermissionsForRole('President');
// Returns: ['view_dashboard', 'view_org_reports', ...]

// Check specific permission
const canPublish = hasPermission('Vice President', 'publish_announcements');
// Returns: false (only President can publish)

// Check dashboard access
const canAccessFinance = canAccessPage('Treasurer', 'finance');
// Returns: true
```

---

## Notes

1. **Publishing Announcements**: Only Tier 1 (President) can publish announcements. Tier 2 can create, edit, and delete, but publishing requires President approval.

2. **Officer Account Approval**: Only Tier 1 can approve officer accounts.

3. **System Settings**: Only Tier 1 can modify system settings.

4. **VP Override**: Tier 1 can override decisions made by Tier 2 (VPs).

5. **Tier 3 Specialization**: Each Tier 3 sub-category has unique permissions tailored to their specific responsibilities.

6. **Role Normalization**: Role names are normalized (lowercase, trimmed) when matching, so "Vice President" and "vice president" are treated the same.







