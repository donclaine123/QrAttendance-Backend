const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const db = require("../db");

// 📌 Configure Nodemailer for sending emails
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// 📌 Register User
exports.register = async (req, res) => {
    const { role, email, firstName, lastName, password, studentId } = req.body;

    try {
        // 🔹 Check if email already exists
        const [teacherRows] = await db.query("SELECT id FROM teachers WHERE email = ?", [email]);
        if (teacherRows.length > 0) {
            return res.status(400).json({ success: false, message: "Email already registered as a teacher." });
        }

        const [studentRows] = await db.query("SELECT id FROM students WHERE email = ?", [email]);
        if (studentRows.length > 0) {
            return res.status(400).json({ success: false, message: "Email already registered as a student." });
        }

        // 🔹 Hash password and generate verification token
        const hashedPassword = await bcrypt.hash(password, 10);
        const verificationToken = crypto.randomBytes(32).toString("hex");

        if (role === "teacher") {
            await db.query(
                "INSERT INTO teachers (email, password, first_name, last_name, verification_token, is_verified) VALUES (?, ?, ?, ?, ?, ?)",
                [email, hashedPassword, firstName, lastName, verificationToken, false] // `is_verified` is `false` initially
            );
        } else if (role === "student") {
            await db.query(
                "INSERT INTO students (email, password, first_name, last_name, student_id, verification_token, is_verified) VALUES (?, ?, ?, ?, ?, ?, ?)",
                [email, hashedPassword, firstName, lastName, studentId, verificationToken, false]
            );
        } else {
            return res.status(400).json({ success: false, message: "Invalid role" });
        }

        // 🔹 Send verification email
        const verifyUrl = `https://your-frontend-url.com/verify?token=${verificationToken}`;
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Verify Your Email",
            html: `<p>Click <a href="${verifyUrl}">here</a> to verify your email.</p>`
        });

        res.json({ success: true, message: "Registration successful! Check your email for verification." });

    } catch (err) {
        console.error("Registration error:", err);
        res.status(500).json({ success: false, message: "Server error" });
    }
};

// 📌 Verify Email
exports.verifyEmail = async (req, res) => {
    const { token } = req.query;

    try {
        // 🔹 Check teachers table
        const [teacherRows] = await db.query("SELECT id FROM teachers WHERE verification_token = ?", [token]);
        if (teacherRows.length > 0) {
            await db.query(
                "UPDATE teachers SET is_verified = TRUE, verification_token = NULL WHERE id = ?",
                [teacherRows[0].id]
            );
            return res.json({ success: true, message: "Email verified! You can now log in." });
        }

        // 🔹 Check students table
        const [studentRows] = await db.query("SELECT id FROM students WHERE verification_token = ?", [token]);
        if (studentRows.length > 0) {
            await db.query(
                "UPDATE students SET is_verified = TRUE, verification_token = NULL WHERE id = ?",
                [studentRows[0].id]
            );
            return res.json({ success: true, message: "Email verified! You can now log in." });
        }

        // 🔹 If no matching token
        res.status(400).json({ success: false, message: "Invalid or expired token." });

    } catch (err) {
        console.error("Verification error:", err);
        res.status(500).json({ success: false, message: "Server error" });
    }
};

// 📌 Login Function
exports.login = async (req, res) => {
    const { email, password } = req.body;

    try {
        // 🔹 Check if user exists in the teachers table
        const [teacherRows] = await db.query("SELECT id, password, is_verified FROM teachers WHERE email = ?", [email]);
        if (teacherRows.length > 0) {
            const teacher = teacherRows[0];

            // 🔹 Check email verification
            if (!teacher.is_verified) {
                return res.status(401).json({ success: false, message: "Please verify your email before logging in." });
            }

            // 🔹 Check password
            const passwordMatch = await bcrypt.compare(password, teacher.password);
            if (passwordMatch) {
                return res.json({ success: true, role: "teacher", userId: teacher.id });
            } else {
                return res.status(401).json({ success: false, message: "Invalid credentials" });
            }
        }

        // 🔹 Check if user exists in the students table
        const [studentRows] = await db.query("SELECT id, password, is_verified FROM students WHERE email = ?", [email]);
        if (studentRows.length > 0) {
            const student = studentRows[0];

            // 🔹 Check email verification
            if (!student.is_verified) {
                return res.status(401).json({ success: false, message: "Please verify your email before logging in." });
            }

            // 🔹 Check password
            const passwordMatch = await bcrypt.compare(password, student.password);
            if (passwordMatch) {
                return res.json({ success: true, role: "student", userId: student.id });
            } else {
                return res.status(401).json({ success: false, message: "Invalid credentials" });
            }
        }

        // 🔹 If email not found in both tables
        res.status(401).json({ success: false, message: "Invalid credentials" });

    } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ success: false, message: "Server error" });
    }
};

