const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const QRCode = require("qrcode");

const app = express();
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Mock database
const users = [
  { id: 1, email: "teacher@example.com", password: "teacher123", role: "teacher" },
  { id: 2, email: "student@example.com", password: "student123", role: "student" },
];

const sessions = [];
const attendance = [];

// Login endpoint
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  const user = users.find((u) => u.email === email && u.password === password);

  if (user) {
    res.json({ success: true, role: user.role, userId: user.id });
  } else {
    res.status(401).json({ success: false, message: "Invalid credentials" });
  }
});

// Generate QR code endpoint
app.post("/generate-qr", async (req, res) => {
  const { sessionId } = req.body;
  const qrData = JSON.stringify({ sessionId, timestamp: Date.now() });

  try {
    const qrCodeUrl = await QRCode.toDataURL(qrData);
    sessions.push({ sessionId, qrData });
    res.json({ success: true, qrCodeUrl });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to generate QR code" });
  }
});

// Scan QR code endpoint
app.post("/scan-qr", (req, res) => {
  const { qrData, studentId } = req.body;
  console.log("Received QR data:", qrData);
  console.log("Received student ID:", studentId);

  try {
    const qrDataParsed = JSON.parse(qrData); // Parse the QR code data
    console.log("Parsed QR data:", qrDataParsed);

    const session = sessions.find((s) => s.sessionId === qrDataParsed.sessionId);

    if (session) {
      console.log("Session found:", session);

      // Check if the student has already marked attendance for this session
      const existingRecord = attendance.find(
        (record) => record.sessionId === session.sessionId && record.studentId === studentId
      );

      if (existingRecord) {
        console.log("Duplicate attendance detected:", existingRecord);
        res.status(400).json({ success: false, message: "Attendance already marked for this session." });
      } else {
        // Add a new attendance record
        const newRecord = { sessionId: session.sessionId, studentId, status: "Present", timestamp: Date.now() };
        attendance.push(newRecord);
        console.log("New attendance record added:", newRecord);
        res.json({ success: true, message: "Attendance marked successfully" });
      }
    } else {
      console.log("Invalid QR code:", qrData);
      res.status(400).json({ success: false, message: "Invalid QR code" });
    }
  } catch (err) {
    console.error("Error parsing QR data:", err);
    res.status(400).json({ success: false, message: "Invalid QR code format" });
  }
});

// View attendance endpoint
app.get("/attendance", (req, res) => {
  res.json({ success: true, attendance });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});