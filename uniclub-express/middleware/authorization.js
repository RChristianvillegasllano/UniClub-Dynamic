/**
 * Authorization Middleware
 * Protects against logic-based vulnerabilities, IDOR, and privilege escalation
 */

import pool from '../config/db.js';

// ============================================
// 1. ROLE-BASED ACCESS CONTROL (RBAC)
// ============================================

/**
 * Check if user has required role
 */
export function hasRole(user, requiredRoles) {
  if (!user || !user.role) return false;
  
  const userRole = (user.role || '').toLowerCase();
  const roles = Array.isArray(requiredRoles) ? requiredRoles : [requiredRoles];
  
  return roles.some(role => userRole.includes(role.toLowerCase()));
}

/**
 * Check if user has required permission
 */
export function hasPermission(user, requiredPermission) {
  if (!user) return false;
  
  // Admin has all permissions
  if (user.admin) return true;
  
  // Check officer permissions
  if (user.permissions) {
    let perms = user.permissions;
    
    // Parse if string
    if (typeof perms === 'string') {
      try {
        perms = JSON.parse(perms);
      } catch {
        return false;
      }
    }
    
    // Check if permission exists
    if (Array.isArray(perms)) {
      return perms.includes(requiredPermission);
    }
    
    if (typeof perms === 'object') {
      return perms[requiredPermission] === true;
    }
  }
  
  return false;
}

/**
 * Middleware to require specific role
 */
export const requireRole = (...roles) => {
  return (req, res, next) => {
    const user = req.session?.admin || req.session?.officer || req.session?.student;
    
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        error: 'Authentication required' 
      });
    }
    
    if (!hasRole(user, roles)) {
      console.warn(`[AUTHORIZATION] Role check failed for ${user.id || user.email} - required: ${roles.join(', ')}, has: ${user.role}`);
      return res.status(403).json({ 
        success: false, 
        error: 'Insufficient permissions' 
      });
    }
    
    next();
  };
};

/**
 * Middleware to require specific permission
 */
export const requirePermission = (permission) => {
  return (req, res, next) => {
    const user = req.session?.admin || req.session?.officer;
    
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        error: 'Authentication required' 
      });
    }
    
    // Admin bypass
    if (req.session?.admin) {
      return next();
    }
    
    if (!hasPermission(user, permission)) {
      console.warn(`[AUTHORIZATION] Permission check failed for ${user.id || user.email} - required: ${permission}`);
      return res.status(403).json({ 
        success: false, 
        error: 'Insufficient permissions' 
      });
    }
    
    next();
  };
};

// ============================================
// 2. IDOR (Insecure Direct Object Reference) PROTECTION
// ============================================

/**
 * Verify user owns the resource they're trying to access
 */
export async function verifyResourceOwnership(resourceType, resourceId, userId, userRole) {
  try {
    // Admin can access any resource
    if (userRole === 'admin' || userRole === 'Admin') {
      return true;
    }
    
    switch (resourceType) {
      case 'student':
        const [studentResult] = await pool.query(
          'SELECT id FROM students WHERE id = ?',
          [resourceId]
        );
        if (studentResult.rows.length === 0) return false;
        // Students can only access their own data
        return studentResult.rows[0].id === userId;
        
      case 'officer':
        const [officerResult] = await pool.query(
          'SELECT id, club_id FROM officers WHERE id = ?',
          [resourceId]
        );
        if (officerResult.rows.length === 0) return false;
        const officer = officerResult.rows[0];
        // Officers can access their own data or data from same club
        if (officer.id === userId) return true;
        // Check if same club (for officers)
        const [userOfficer] = await pool.query(
          'SELECT club_id FROM officers WHERE id = ?',
          [userId]
        );
        if (userOfficer.rows.length > 0) {
          return userOfficer.rows[0].club_id === officer.club_id;
        }
        return false;
        
      case 'event':
        const [eventResult] = await pool.query(
          'SELECT club_id, created_by FROM events WHERE id = ?',
          [resourceId]
        );
        if (eventResult.rows.length === 0) return false;
        const event = eventResult.rows[0];
        // Officers can access events from their club
        if (userRole && userRole.toLowerCase().includes('officer')) {
          const [userClub] = await pool.query(
            'SELECT club_id FROM officers WHERE id = ?',
            [userId]
          );
          if (userClub.rows.length > 0) {
            return userClub.rows[0].club_id === event.club_id;
          }
        }
        return false;
        
      default:
        return false;
    }
  } catch (error) {
    console.error('[AUTHORIZATION] Error verifying resource ownership:', error);
    return false;
  }
}

/**
 * Middleware to protect against IDOR
 */
export const protectResource = (resourceType, idParam = 'id') => {
  return async (req, res, next) => {
    const resourceId = req.params[idParam] || req.body[idParam] || req.query[idParam];
    
    if (!resourceId) {
      return res.status(400).json({ 
        success: false, 
        error: 'Resource ID required' 
      });
    }
    
    const user = req.session?.admin || req.session?.officer || req.session?.student;
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        error: 'Authentication required' 
      });
    }
    
    const userId = user.id;
    const userRole = req.session?.admin ? 'admin' : (req.session?.officer ? 'officer' : 'student');
    
    const hasAccess = await verifyResourceOwnership(resourceType, resourceId, userId, userRole);
    
    if (!hasAccess) {
      console.warn(`[AUTHORIZATION] IDOR attempt blocked - User ${userId} tried to access ${resourceType} ${resourceId}`);
      return res.status(403).json({ 
        success: false, 
        error: 'Access denied' 
      });
    }
    
    next();
  };
};

// ============================================
// 3. PRIVILEGE ESCALATION PROTECTION
// ============================================

/**
 * Prevent users from modifying their own role/permissions
 */
export const preventSelfPrivilegeEscalation = (req, res, next) => {
  const user = req.session?.admin || req.session?.officer;
  if (!user) return next();
  
  const targetId = req.params.id || req.body.id;
  const userId = user.id;
  
  // Prevent users from modifying their own role/permissions
  if (targetId && String(targetId) === String(userId)) {
    if (req.body.role || req.body.permissions || req.body.status) {
      console.warn(`[AUTHORIZATION] Self-privilege escalation attempt blocked for user ${userId}`);
      return res.status(403).json({ 
        success: false, 
        error: 'Cannot modify your own role or permissions' 
      });
    }
  }
  
  next();
};

/**
 * Validate that role changes are valid
 */
export const validateRoleChange = async (req, res, next) => {
  const newRole = req.body.role;
  const targetId = req.params.id || req.body.id;
  
  if (!newRole || !targetId) return next();
  
  // Only admin can change roles
  if (!req.session?.admin) {
    return res.status(403).json({ 
      success: false, 
      error: 'Only administrators can change roles' 
    });
  }
  
  // Validate role is in allowed list
  const allowedRoles = [
    'President', 'Vice President', 'Secretary', 'Treasurer', 
    'Auditor', 'Public Relations Officer', 'Member'
  ];
  
  if (!allowedRoles.includes(newRole)) {
    return res.status(400).json({ 
      success: false, 
      error: 'Invalid role' 
    });
  }
  
  next();
};

// ============================================
// 4. CLUB MEMBERSHIP VERIFICATION
// ============================================

/**
 * Verify user belongs to the club they're trying to access
 */
export async function verifyClubMembership(clubId, userId, userRole) {
  try {
    // Admin can access any club
    if (userRole === 'admin') {
      return true;
    }
    
    // Check if officer belongs to club
    if (userRole === 'officer') {
      const [result] = await pool.query(
        'SELECT club_id FROM officers WHERE id = ?',
        [userId]
      );
      if (result.rows.length === 0) return false;
      return result.rows[0].club_id === parseInt(clubId);
    }
    
    // Check if student is member of club
    if (userRole === 'student') {
      const [result] = await pool.query(
        'SELECT club_id FROM club_members WHERE student_id = ? AND club_id = ?',
        [userId, clubId]
      );
      return result.rows.length > 0;
    }
    
    return false;
  } catch (error) {
    console.error('[AUTHORIZATION] Error verifying club membership:', error);
    return false;
  }
}

/**
 * Middleware to protect club resources
 */
export const protectClubResource = (clubIdParam = 'club_id') => {
  return async (req, res, next) => {
    const clubId = req.params[clubIdParam] || req.body[clubIdParam] || req.query[clubIdParam];
    
    if (!clubId) {
      return res.status(400).json({ 
        success: false, 
        error: 'Club ID required' 
      });
    }
    
    const user = req.session?.admin || req.session?.officer || req.session?.student;
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        error: 'Authentication required' 
      });
    }
    
    const userId = user.id;
    const userRole = req.session?.admin ? 'admin' : (req.session?.officer ? 'officer' : 'student');
    
    const hasAccess = await verifyClubMembership(clubId, userId, userRole);
    
    if (!hasAccess) {
      console.warn(`[AUTHORIZATION] Club access denied - User ${userId} tried to access club ${clubId}`);
      return res.status(403).json({ 
        success: false, 
        error: 'Access denied to this club resource' 
      });
    }
    
    next();
  };
};

export default {
  hasRole,
  hasPermission,
  requireRole,
  requirePermission,
  verifyResourceOwnership,
  protectResource,
  preventSelfPrivilegeEscalation,
  validateRoleChange,
  verifyClubMembership,
  protectClubResource
};

