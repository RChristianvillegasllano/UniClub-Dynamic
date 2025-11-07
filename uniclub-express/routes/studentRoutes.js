// routes/studentRoutes.js
import express from "express";
const router = express.Router();

// Example route for students
router.get("/", (req, res) => {
  res.send("Student route is working!");
});

export default router;
