// models/requirementsModel.js
import pool from "../config/db.js";

// Get all requirements
export const getAllRequirements = async () => {
  const result = await pool.query("SELECT * FROM requirements ORDER BY id DESC");
  return result.rows;
};

// Add a new requirement
export const addRequirement = async ({ title, description, priority, status }) => {
  await pool.query(
    "INSERT INTO requirements (title, description, priority, status) VALUES ($1, $2, $3, $4)",
    [title, description, priority, status]
  );
};

// Update a requirement
export const updateRequirement = async (id, { title, description, priority, status }) => {
  await pool.query(
    `UPDATE requirements 
     SET title = $1, description = $2, priority = $3, status = $4 
     WHERE id = $5`,
    [title, description, priority, status, id]
  );
};

// Delete a requirement
export const deleteRequirement = async (id) => {
  await pool.query("DELETE FROM requirements WHERE id = $1", [id]);
};
