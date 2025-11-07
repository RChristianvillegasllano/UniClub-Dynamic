// routes/requirementsRoutes.js
import express from "express";
import {
  list,
  add,
  edit,
  deleteRequirementHandler,
} from "../controllers/requirementsController.js";

const router = express.Router();

router.get("/", list);
router.post("/add", add);
router.post("/edit/:id", edit);
router.post("/delete/:id", deleteRequirementHandler);

export default router;