import pool from "../config/db.js";

/**
 * Auto-update event statuses based on current date/time
 * - Sets to "Ongoing" if event date is today (or between date and end_date)
 * - Sets to "Completed" if end_date has passed (after midnight)
 * - Only updates approved events (not pending/rejected)
 * - Automatically deletes RSVPs for events that have ended
 */
export async function updateEventStatuses() {
  try {
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const todayStr = today.toISOString().split('T')[0]; // YYYY-MM-DD
    const nowStr = now.toISOString().slice(0, 19).replace('T', ' '); // YYYY-MM-DD HH:MM:SS
    
    // Update events to "Ongoing" if today is between date and end_date
    // This includes events that start today or are currently happening
    const ongoingResult = await pool.query(`
      UPDATE events 
      SET status = 'Ongoing'
      WHERE COALESCE(status, 'pending_approval') NOT IN ('pending_approval', 'rejected', 'Completed', 'completed', 'Cancelled', 'cancelled')
        AND date IS NOT NULL
        AND DATE(date) <= ?
        AND COALESCE(DATE(end_date), DATE(date)) >= ?
        AND status != 'Ongoing'
        AND status != 'ongoing'
    `, [todayStr, todayStr]);
    
    if (ongoingResult.affectedRows > 0) {
      console.log(`[Event Status Update] Updated ${ongoingResult.affectedRows} event(s) to "Ongoing"`);
    }
    
    // Update events to "Completed" if end_date has passed (after midnight)
    // For multi-day events, only mark as Completed after end_date has fully passed
    await pool.query(`
      UPDATE events 
      SET status = 'Completed'
      WHERE COALESCE(status, 'pending_approval') NOT IN ('pending_approval', 'rejected', 'Completed', 'completed', 'Cancelled', 'cancelled')
        AND end_date IS NOT NULL
        AND DATE(end_date) < ?
        AND (
          status IS NULL 
          OR status = 'Scheduled' 
          OR status = 'scheduled'
          OR status = 'Ongoing'
          OR status = 'ongoing'
          OR status = 'Upcoming'
          OR status = 'upcoming'
        )
    `, [todayStr]);
    
    // Also handle events with only date (no end_date) - mark as Completed if date has passed
    await pool.query(`
      UPDATE events 
      SET status = 'Completed'
      WHERE COALESCE(status, 'pending_approval') NOT IN ('pending_approval', 'rejected', 'Completed', 'completed', 'Cancelled', 'cancelled')
        AND date IS NOT NULL
        AND end_date IS NULL
        AND DATE(date) < ?
        AND (
          status IS NULL 
          OR status = 'Scheduled' 
          OR status = 'scheduled'
          OR status = 'Ongoing'
          OR status = 'ongoing'
          OR status = 'Upcoming'
          OR status = 'upcoming'
        )
    `, [todayStr]);
    
    // Clean up RSVPs for completed events (events that have ended)
    // Delete RSVPs for events that are marked as Completed or have end_date in the past
    const cleanupResult = await pool.query(`
      DELETE ea FROM event_attendance ea
      INNER JOIN events e ON ea.event_id = e.id
      WHERE (
        e.status IN ('Completed', 'completed')
        OR (
          e.end_date IS NOT NULL 
          AND DATE(e.end_date) < ?
        )
        OR (
          e.end_date IS NULL 
          AND e.date IS NOT NULL 
          AND DATE(e.date) < ?
        )
      )
      AND COALESCE(e.status, 'pending_approval') NOT IN ('pending_approval', 'rejected', 'Cancelled', 'cancelled')
    `, [todayStr, todayStr]);
    
    if (cleanupResult.affectedRows > 0) {
      console.log(`[Event Status Update] Cleaned up ${cleanupResult.affectedRows} RSVP(s) for ended events`);
    }
    
    console.log(`[Event Status Update] Updated event statuses at ${nowStr}`);
  } catch (err) {
    console.error("[Event Status Update] Error updating event statuses:", err.message);
  }
}

