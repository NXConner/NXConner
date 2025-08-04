import express from "express";
import { json, urlencoded } from "body-parser";

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(json());
app.use(urlencoded({ extended: true }));

// Basic health check route
app.get("/health", (req, res) => {
  res.status(200).json({ status: "OK", message: "Blacktop Blackout API is running" });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

export default app;