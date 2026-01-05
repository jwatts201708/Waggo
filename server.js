import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mongoose from "mongoose";

import personRoutes from "./routes/personRoutes.js";

dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.use("/api/person", personRoutes);

// Root route
app.get("/", (req, res) => {
  res.send("Waggo API is live");
});

// MongoDB connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB error:", err));

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
