import express from "express";
import dotenv from "dotenv";
import session from "express-session";
import path from "path";
import { fileURLToPath } from "url";
import requirementsRoutes from "./routes/requirementsRoutes.js";
import adminRoutes from "./routes/adminRoutes.js";
import apiRoutes from "./routes/apiRoutes.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// ESM-friendly __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Views + static
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));

// Body parsers
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Session
app.use(
  session({
    secret: process.env.SESSION_SECRET || "change-me",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: "lax", secure: false, maxAge: 86400000 },
  })
);

// Routes
app.use("/requirements", requirementsRoutes);
app.use("/admin", adminRoutes);
app.use("/api", apiRoutes);

// Root
app.get("/", (_req, res) => res.redirect("/requirements"));

// 404
app.use((req, res) => res.status(404).render("errors/404", { title: "Not Found" }));

// Error handler
app.use((err, req, res, _next) => {
  console.error(err);
  res.status(500).render("errors/500", { title: "Server Error", error: err });
});

app.listen(PORT, () => console.log(`🚀 http://localhost:${PORT}`));
