/**
 * TIER PERMISSIONS CONFIGURATION
 * 
 * This file defines the hierarchical permission system for club officers.
 * Roles are organized into tiers with specific permissions and dashboard visibility.
 */

/**
 * 🟥 TIER 1 – EXECUTIVE LEVEL (FULL POWER)
 * 
 * Roles:
 * - President
 * - Supremo / Grand Peer / Head / Adviser / Chairperson (Highest Role Equivalent)
 * 
 * All counted as President-tier.
 */
const TIER_1_ROLES = [
  'president',
  'supremo',
  'grand peer',
  'head',
  'adviser',
  'chairperson',
  'chief executive',
  'executive head'
];

const TIER_1_PERMISSIONS = [
  // Full CRUD on all modules
  'view_dashboard',
  'view_org_reports',
  'export_reports',
  'view_analytics',
  'generate_custom_reports',
  
  // Clubs
  'view_clubs',
  'create_clubs',
  'edit_clubs',
  'delete_clubs',
  
  // Officers
  'view_officers',
  'add_officers',
  'edit_officers',
  'remove_officers',
  'approve_officer_accounts',
  'manage_officer_roles',
  
  // Members (full access)
  'view_members',
  'add_members',
  'edit_members',
  'remove_members',
  'approve_applications',
  
  // Events
  'view_events',
  'create_events',
  'edit_events',
  'cancel_events',
  'delete_events',
  'manage_attendance',
  'export_event_reports',
  
  // Finance
  'view_financial_records',
  'record_transactions',
  'approve_expenses',
  'generate_financial_reports',
  'manage_budget',
  'delete_financial_records',
  'audit_finances',
  
  // Attendance
  'view_attendance',
  'create_attendance',
  'edit_attendance',
  'delete_attendance',
  'export_attendance_reports',
  
  // Documents
  'view_documents',
  'upload_documents',
  'edit_documents',
  'delete_documents',
  'download_documents',
  'manage_minutes',
  
  // Announcements
  'view_announcements',
  'post_announcements',
  'publish_announcements',
  'edit_announcements',
  'delete_announcements',
  'send_notifications',
  'manage_social_media',
  
  // System
  'view_system_settings',
  'modify_system_settings',
  'manage_permissions',
  'view_audit_logs',
  'backup_system',
  'system_maintenance',
  'override_vp_decisions',
  'create_executive_reports',
  'access_activity_logs'
];

const TIER_1_DASHBOARD_PAGES = [
  'all' // All pages visible
];

/**
 * 🟧 TIER 2 – MANAGEMENT LEVEL (Vice Presidents + High Officers)
 * 
 * All of the following belong here (same level of power):
 * - Vice-President Internal
 * - Vice-President External
 * - Executive VP
 * - VP Finance
 * - VP Logistics
 * - VP Production
 * - VP Creatives
 * - VP Promotion & Communication
 * - VP Religious / VP Social
 * - Internal & External VP (Red Cross / Peer Facilitators)
 * - Interyor Heneral
 * - Heneral Pangkayapaan
 * - Punong Konsehal
 * - 1st–4th Konsehal
 * - Kalihim Heneral
 * - Heneral Pampinansyal
 * - Heneral Pangkomunikasyon
 */
const TIER_2_ROLES = [
  'vice president',
  'vice-president',
  'vice president internal',
  'vice-president internal',
  'vice president external',
  'vice-president external',
  'executive vp',
  'vp finance',
  'vp logistics',
  'vp production',
  'vp creatives',
  'vp promotion & communication',
  'vp promotion and communication',
  'vp religious',
  'vp social',
  'internal vp',
  'external vp',
  'interyor heneral',
  'heneral pangkayapaan',
  'punong konsehal',
  '1st konsehal',
  '2nd konsehal',
  '3rd konsehal',
  '4th konsehal',
  'kalihim heneral',
  'heneral pampinansyal',
  'heneral pangkomunikasyon'
];

const TIER_2_PERMISSIONS = [
  // Dashboard & Reports
  'view_dashboard',
  'view_org_reports',
  'export_reports',
  'view_analytics',
  
  // Announcements (Create + Update + Delete, but PUBLISH requires President)
  'view_announcements',
  'create_announcements',
  'edit_announcements',
  'delete_announcements',
  'send_notifications',
  // Note: publish_announcements is NOT included - requires President approval
  
  // Events
  'view_events',
  'create_events',
  'edit_events',
  'cancel_events',
  'manage_attendance',
  'export_event_reports',
  
  // Committees
  'view_committees',
  'create_committees',
  'edit_committees',
  'delete_committees',
  'manage_committee_tasks',
  
  // Members
  'view_members',
  'add_members',
  'edit_members',
  'remove_members',
  'approve_applications',
  
  // Attendance
  'view_attendance',
  'create_attendance',
  'edit_attendance',
  'export_attendance_reports',
  
  // Inventory / Logistics
  'view_inventory',
  'manage_inventory',
  'manage_logistics',
  
  // Finance (View only)
  'view_financial_records',
  'view_financial_reports',
  
  // Logs (View only)
  'view_audit_logs',
  
  // Documents
  'view_documents',
  'upload_documents',
  'edit_documents',
  'download_documents',
  
  // Note: Cannot approve officer accounts
  // Note: Cannot change system settings
];

const TIER_2_DASHBOARD_PAGES = [
  'home', // dashboard home (required for all officers)
  'announcements',
  'events',
  'committees',
  'members',
  'attendance',
  'inventory',
  'reports',
  'finance' // read only
];

/**
 * 🟡 TIER 3 – MID-LEVEL (UNIQUE PER ROLE)
 * 
 * Tier 3 is NOT equal power. Each officer has distinct permissions depending on the nature of their job.
 */

// TIER 3A — Documentation Roles
const TIER_3A_ROLES = [
  'secretary',
  'organizational secretary',
  'corresponding secretary',
  'recording secretary'
];

const TIER_3A_PERMISSIONS = [
  'view_dashboard',
  'view_events',
  'view_members',
  
  // Meeting Minutes
  'view_minutes',
  'create_minutes',
  'edit_minutes',
  'delete_minutes',
  
  // Internal Documents
  'view_documents',
  'upload_documents',
  'edit_documents',
  'delete_documents',
  'download_documents',
  
  // Requirements/Forms
  'upload_requirements',
  'upload_forms',
  
  // Attendance Remarks (Create only)
  'create_attendance_remarks'
];

const TIER_3A_DASHBOARD_PAGES = [
  'home', // dashboard home (required for all officers)
  'meeting_minutes',
  'documents',
  'events', // view only
  'members' // view only
];

// TIER 3B — Finance Roles
const TIER_3B_TREASURER_ROLES = [
  'treasurer',
  'executive treasurer',
  'assistant treasurer',
  'finance & accounting',
  'finance and accounting',
  'business & finance officer',
  'business and finance officer',
  'financial officer',
  'financial officers'
];

const TIER_3B_TREASURER_PERMISSIONS = [
  'view_dashboard',
  'view_members',
  'view_events',
  
  // Full Finance CRUD
  'view_financial_records',
  'record_transactions',
  'create_transactions',
  'edit_transactions',
  'delete_transactions',
  'approve_expenses',
  'generate_financial_reports',
  'manage_budget',
  
  // Receipts
  'upload_receipts',
  'view_receipts',
  
  // Income & Expenses
  'track_income',
  'track_expenses',
  'generate_financial_statements'
];

const TIER_3B_TREASURER_DASHBOARD_PAGES = [
  'home', // dashboard home (required for all officers)
  'finance',
  'expense_reports',
  'members', // view
  'events' // view
];

const TIER_3B_AUDITOR_ROLES = [
  'auditor',
  'peer auditor',
  'assistant auditor'
];

const TIER_3B_AUDITOR_PERMISSIONS = [
  'view_dashboard',
  'view_members',
  'view_events',
  
  // Finance (View + Comment only)
  'view_financial_records',
  'view_financial_reports',
  'comment_on_finance',
  
  // Audit Functions
  'approve_treasurer_reports',
  'validate_treasurer_reports',
  'generate_audit_findings',
  'view_audit_logs'
];

const TIER_3B_AUDITOR_DASHBOARD_PAGES = [
  'home', // dashboard home (required for all officers)
  'audit_logs',
  'finance', // view/comment only
  'members', // view
  'events' // view
];

// TIER 3C — Public Relations Roles
const TIER_3C_ROLES = [
  'pio',
  'pro',
  'public relations officer',
  'public information officer',
  'public information officer 1',
  'public information officer 2'
];

const TIER_3C_PERMISSIONS = [
  'view_dashboard',
  'view_events',
  
  // Announcement Drafts
  'view_announcements',
  'create_announcement_drafts',
  'edit_announcement_drafts',
  
  // Publicity
  'create_publicity_writeups',
  'upload_posters',
  
  // Note: Cannot publish announcements (President only)
];

const TIER_3C_DASHBOARD_PAGES = [
  'home', // dashboard home (required for all officers)
  'announcement_drafts',
  'events' // view only
];

// TIER 3G — Press/Media Roles (Very Limited Access)
const TIER_3G_ROLES = [
  'press',
  'media',
  'press officer',
  'media officer',
  'journalist',
  'reporter'
];

const TIER_3G_PERMISSIONS = [
  'view_dashboard',
  'view_events', // view only, no create/edit
  'view_announcements', // view only, no create/edit
  // Note: Press can only VIEW content, cannot modify anything
];

const TIER_3G_DASHBOARD_PAGES = [
  'home', // dashboard home only
  'events' // view only
];

// TIER 3D — Logistics, Production, and Technical Roles
const TIER_3D_ROLES = [
  'logistics officer',
  'vp logistics',
  'event logistics',
  'production',
  'stage & decor leads',
  'stage and decor leads',
  'tech lead',
  'audio-visual',
  'multimedia',
  'creatives',
  'business manager'
];

const TIER_3D_PERMISSIONS = [
  'view_dashboard',
  'view_events',
  
  // Equipment Inventory
  'view_inventory',
  'create_inventory',
  'edit_inventory',
  'delete_inventory',
  'manage_equipment_inventory',
  
  // Production Materials
  'handle_production_materials',
  'upload_event_requirements',
  'assist_organizers'
];

const TIER_3D_DASHBOARD_PAGES = [
  'home', // dashboard home (required for all officers)
  'inventory',
  'event_materials',
  'events' // view only
];

// TIER 3E — Year-Level Representatives
const TIER_3E_ROLES = [
  '1st year representative',
  'first year representative',
  '2nd year representative',
  'second year representative',
  '3rd year representative',
  'third year representative',
  '4th year representative',
  'fourth year representative',
  'year representative'
];

const TIER_3E_PERMISSIONS = [
  'view_dashboard',
  'view_events',
  'view_attendance',
  
  // Attendance (Validate - Create only)
  'validate_attendance',
  'create_attendance',
  
  // Reports
  'submit_reports',
  
  // Note: Cannot edit events or finances
];

const TIER_3E_DASHBOARD_PAGES = [
  'home', // dashboard home (required for all officers)
  'events', // view only
  'attendance', // view only
  'submissions'
];

// TIER 3F — Committee Heads
const TIER_3F_ROLES = [
  'shepherding',
  'outreach',
  'social affairs',
  'religious affairs',
  'community extension coordinator',
  'committee',
  'committee head',
  'committee chair'
];

const TIER_3F_PERMISSIONS = [
  'view_dashboard',
  'view_events',
  
  // Committee Management
  'view_committees',
  'create_committees',
  'edit_committees',
  'delete_committees',
  'manage_committee_tasks',
  
  // Reports
  'submit_reports'
];

const TIER_3F_DASHBOARD_PAGES = [
  'home', // dashboard home (required for all officers)
  'committee',
  'events', // view only
  'submissions'
];

/**
 * 🟩 TIER 4 – ENTRY LEVEL / GENERAL MEMBERS
 * 
 * (All clubs have Members, Volunteers, or Non-officer accounts)
 */
const TIER_4_ROLES = [
  'member',
  'members',
  'volunteer',
  'volunteers',
  'non-officer'
];

const TIER_4_PERMISSIONS = [
  'view_dashboard',
  'view_announcements',
  'view_events',
  'submit_attendance',
  'submit_forms'
];

const TIER_4_DASHBOARD_PAGES = [
  'home',
  'events',
  'announcements'
];

/**
 * ROLE TO TIER MAPPING
 * Maps role names (normalized) to their tier level
 */
const ROLE_TO_TIER = {
  // Tier 1
  ...Object.fromEntries(TIER_1_ROLES.map(role => [role.toLowerCase(), 1])),
  
  // Tier 2
  ...Object.fromEntries(TIER_2_ROLES.map(role => [role.toLowerCase(), 2])),
  
  // Tier 3A
  ...Object.fromEntries(TIER_3A_ROLES.map(role => [role.toLowerCase(), '3A'])),
  
  // Tier 3B - Treasurer
  ...Object.fromEntries(TIER_3B_TREASURER_ROLES.map(role => [role.toLowerCase(), '3B-T'])),
  
  // Tier 3B - Auditor
  ...Object.fromEntries(TIER_3B_AUDITOR_ROLES.map(role => [role.toLowerCase(), '3B-A'])),
  
  // Tier 3C
  ...Object.fromEntries(TIER_3C_ROLES.map(role => [role.toLowerCase(), '3C'])),
  
  // Tier 3D
  ...Object.fromEntries(TIER_3D_ROLES.map(role => [role.toLowerCase(), '3D'])),
  
  // Tier 3E
  ...Object.fromEntries(TIER_3E_ROLES.map(role => [role.toLowerCase(), '3E'])),
  
  // Tier 3F
  ...Object.fromEntries(TIER_3F_ROLES.map(role => [role.toLowerCase(), '3F'])),
  
  // Tier 3G - Press/Media
  ...Object.fromEntries(TIER_3G_ROLES.map(role => [role.toLowerCase(), '3G'])),
  
  // Tier 4
  ...Object.fromEntries(TIER_4_ROLES.map(role => [role.toLowerCase(), 4]))
};

/**
 * TIER PERMISSIONS MAP
 * Maps tier identifiers to their permissions
 */
const TIER_PERMISSIONS = {
  1: TIER_1_PERMISSIONS,
  2: TIER_2_PERMISSIONS,
  '3A': TIER_3A_PERMISSIONS,
  '3B-T': TIER_3B_TREASURER_PERMISSIONS,
  '3B-A': TIER_3B_AUDITOR_PERMISSIONS,
  '3C': TIER_3C_PERMISSIONS,
  '3D': TIER_3D_PERMISSIONS,
  '3E': TIER_3E_PERMISSIONS,
  '3F': TIER_3F_PERMISSIONS,
  '3G': TIER_3G_PERMISSIONS,
  4: TIER_4_PERMISSIONS
};

/**
 * TIER DASHBOARD PAGES MAP
 * Maps tier identifiers to their dashboard page visibility
 */
const TIER_DASHBOARD_PAGES = {
  1: TIER_1_DASHBOARD_PAGES,
  2: TIER_2_DASHBOARD_PAGES,
  '3A': TIER_3A_DASHBOARD_PAGES,
  '3B-T': TIER_3B_TREASURER_DASHBOARD_PAGES,
  '3B-A': TIER_3B_AUDITOR_DASHBOARD_PAGES,
  '3C': TIER_3C_DASHBOARD_PAGES,
  '3D': TIER_3D_DASHBOARD_PAGES,
  '3E': TIER_3E_DASHBOARD_PAGES,
  '3F': TIER_3F_DASHBOARD_PAGES,
  '3G': TIER_3G_DASHBOARD_PAGES,
  4: TIER_4_DASHBOARD_PAGES
};

/**
 * Get tier for a given role
 * @param {string} role - The role name
 * @returns {number|string|null} - The tier level (1, 2, '3A', '3B-T', etc.) or null if not found
 */
export function getTierForRole(role) {
  if (!role) return null;
  const normalizedRole = role.toLowerCase().trim();
  
  // Exact match first
  const exact = ROLE_TO_TIER[normalizedRole];
  if (exact) return exact;

  // Fuzzy match for common president variants to avoid misclassification/403
  // Use word boundary checks to prevent matching "Vice President" as Tier 1
  if (isPresidentRole(role)) {
    return 1; // Treat president variants as Tier 1 (full access)
  }

  return null;
}

/**
 * Check if a role is a president-level role (Tier 1)
 * Uses word boundary checks to prevent matching "Vice President" as president
 * @param {string} role - The role name
 * @returns {boolean} - True if the role is a president-level role
 */
export function isPresidentRole(role) {
  if (!role) return false;
  const normalizedRole = role.toLowerCase().trim();
  
  // If role contains "vice", it's not a president role
  if (normalizedRole.includes('vice')) {
    return false;
  }
  
  // Check if "president" appears as a word (not part of another word)
  const presidentPattern = /\bpresident\b/;
  return presidentPattern.test(normalizedRole);
}

/**
 * Get permissions for a given role
 * @param {string} role - The role name
 * @returns {string[]} - Array of permission strings
 */
export function getPermissionsForRole(role) {
  const tier = getTierForRole(role);
  if (!tier) return [];
  return TIER_PERMISSIONS[tier] || [];
}

/**
 * Get dashboard pages for a given role
 * @param {string} role - The role name
 * @returns {string[]} - Array of dashboard page identifiers
 */
export function getDashboardPagesForRole(role) {
  const tier = getTierForRole(role);
  if (!tier) return [];
  const pages = TIER_DASHBOARD_PAGES[tier] || [];
  
  // Tier 1 has access to all pages
  if (tier === 1 && pages.includes('all')) {
    return ['all'];
  }
  
  return pages;
}

/**
 * Check if a role has a specific permission
 * @param {string} role - The role name
 * @param {string} permission - The permission to check
 * @returns {boolean} - True if the role has the permission
 */
export function hasPermission(role, permission) {
  const permissions = getPermissionsForRole(role);
  return permissions.includes(permission);
}

/**
 * Check if a role can access a dashboard page
 * @param {string} role - The role name
 * @param {string} page - The dashboard page identifier
 * @returns {boolean} - True if the role can access the page
 */
export function canAccessPage(role, page) {
  const pages = getDashboardPagesForRole(role);
  
  // Tier 1 has access to all pages
  if (pages.includes('all')) {
    return true;
  }
  
  return pages.includes(page);
}

/**
 * Get all roles in a specific tier
 * @param {number|string} tier - The tier level
 * @returns {string[]} - Array of role names
 */
export function getRolesInTier(tier) {
  const tierMap = {
    1: TIER_1_ROLES,
    2: TIER_2_ROLES,
    '3A': TIER_3A_ROLES,
    '3B-T': TIER_3B_TREASURER_ROLES,
    '3B-A': TIER_3B_AUDITOR_ROLES,
    '3C': TIER_3C_ROLES,
    '3D': TIER_3D_ROLES,
    '3E': TIER_3E_ROLES,
    '3F': TIER_3F_ROLES,
    '3G': TIER_3G_ROLES,
    4: TIER_4_ROLES
  };
  
  return tierMap[tier] || [];
}

/**
 * Get comprehensive role information
 * @param {string} role - The role name
 * @returns {object} - Object containing tier, permissions, and dashboard pages
 */
export function getRoleInfo(role) {
  const tier = getTierForRole(role);
  return {
    role: role,
    tier: tier,
    permissions: getPermissionsForRole(role),
    dashboardPages: getDashboardPagesForRole(role)
  };
}

// Export all tier definitions for reference
export {
  TIER_1_ROLES,
  TIER_2_ROLES,
  TIER_3A_ROLES,
  TIER_3B_TREASURER_ROLES,
  TIER_3B_AUDITOR_ROLES,
  TIER_3C_ROLES,
  TIER_3D_ROLES,
  TIER_3E_ROLES,
  TIER_3F_ROLES,
  TIER_3G_ROLES,
  TIER_4_ROLES,
  ROLE_TO_TIER,
  TIER_PERMISSIONS,
  TIER_DASHBOARD_PAGES
};

