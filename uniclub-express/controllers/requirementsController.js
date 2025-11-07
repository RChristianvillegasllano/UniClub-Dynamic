// controllers/requirementsController.js
import {
  getAllRequirements,
  addRequirement,
  updateRequirement,
  deleteRequirement,
} from "../models/requirementsModel.js";

// List all
export async function list(req, res) {
  try {
    const requirements = await getAllRequirements();
    res.render("requirements/list", { requirements });
  } catch (err) {
    console.error("❌ Error listing requirements:", err);
    res.status(500).send("Server Error");
  }
}

// Add
export async function add(req, res) {
  try {
    const { title, description, priority, status } = req.body;
    await addRequirement({
      title: title?.trim() || "",
      description: description?.trim() || "",
      priority: priority?.trim() || "normal",
      status: status?.trim() || "open",
    });
    res.redirect("/requirements");
  } catch (err) {
    console.error("❌ Error adding requirement:", err);
    res.status(500).send("Server Error");
  }
}

// Edit
export async function edit(req, res) {
  try {
    const { id } = req.params;
    const { title, description, priority, status } = req.body;
    await updateRequirement(id, {
      title: title?.trim() || "",
      description: description?.trim() || "",
      priority: priority?.trim() || "normal",
      status: status?.trim() || "open",
    });
    res.redirect("/requirements");
  } catch (err) {
    console.error("❌ Error updating requirement:", err);
    res.status(500).send("Server Error");
  }
}

// Delete
export async function deleteRequirementHandler(req, res) {
  try {
    const { id } = req.params;
    await deleteRequirement(id);
    res.redirect("/requirements");
  } catch (err) {
    console.error("❌ Error deleting requirement:", err);
    res.status(500).send("Server Error");
  }
}
