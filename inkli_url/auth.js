// File: ./routes/auth.js

const express = require('express');
const router = express.Router();
const crypto = require('crypto'); // For generating verification tokens
const nodemailer = require('nodemailer'); // For sending emails

/**
 * Exports a function that configures authentication routes.
 * @param {object} client - The connected pg Client instance.
 * @param {string} secretKey - The JWT secret key.
 * @param {object} bcrypt - The bcrypt library instance.
 * @param {object} jwt - The jsonwebtoken library instance.
 * @param {object} emailConfig - Configuration object for nodemailer. Example: { service: 'gmail', auth: { user: 'your_email@gmail.com', pass: 'your_password' } }
 * @param {string} frontendUrl - The base URL of your frontend application (for the verification link).
 * @returns {object} The configured express router.
 */
module.exports = (client, secretKey, bcrypt, jwt, emailConfig, frontendUrl) => {

    // --- Nodemailer Setup ---
    const transporter = nodemailer.createTransport(emailConfig);

    // --- Registration Route ---
    // Path: POST /api/auth/register (relative to mount point in app.js)
    router.post('/register', async (req, res) => {
        const username = req.body.username?.trim(); // Get username, remove whitespace
        const password = req.body.password;
        const email = req.body.email?.trim();
        const fullName = req.body.fullName?.trim();

        // --- Input Validation ---
        if (!username || !password || !email || !fullName) {
            return res.status(400).json({ error: 'Username, password, email, and full name are required.' });
        }
        // Example: Basic password length check
        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
        }
        // Example: Basic username validation (optional)
        if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) { // Allow letters, numbers, underscore, 3-20 chars
            return res.status(400).json({ error: 'Username must be 3-20 characters and contain only letters, numbers, or underscores.' });
        }
        // Example: Basic email validation
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ error: 'Invalid email format.' });
        }
        // Example: Basic full name validation (optional)
        if (!/^[a-zA-Z\s]{2,100}$/.test(fullName)) {
            return res.status(400).json({ error: 'Full name must be 2-100 characters and contain only letters and spaces.' });
        }

        try {
            // --- Check if username or email already exists (before creating verification token) ---
            const existingUser = await client.query(
                'SELECT id FROM users WHERE LOWER(username) = LOWER($1) OR LOWER(email) = LOWER($2)',
                [username, email]
            );

            if (existingUser.rows.length > 0) {
                if (existingUser.rows[0].username === username.toLowerCase()) {
                    return res.status(400).json({ error: 'Username already exists. Please choose another.' });
                } else if (existingUser.rows[0].email === email.toLowerCase()) {
                    return res.status(400).json({ error: 'Email address already exists. Please use another.' });
                }
            }

            // --- Generate Verification Token ---
            const verificationToken = crypto.randomBytes(20).toString('hex');
            const verificationTokenExpiry = new Date(Date.now() + 3600000); // Token expires in 1 hour

            // --- Hash Password ---
            const hashedPassword = await bcrypt.hash(password, 12);

            // --- Store User in Database with Verification Token ---
            await client.query(
                'INSERT INTO users (username, password, email, full_name, bactive, email_verified, verification_token, verification_token_expiry) VALUES (LOWER($1), $2, LOWER($3), $4, $5, $6, $7, $8)',
                [username, hashedPassword, email, fullName, 0, false, verificationToken, verificationTokenExpiry] // bactive is initially 0, email_verified is false
            );

            // --- Send Verification Email ---
            const verificationLink = `${frontendUrl}/verify-email?token=${verificationToken}`;
            const mailOptions = {
                to: email,
                subject: 'Verify Your Email Address',
                html: `<p>Thank you for registering! Please click the following link to verify your email address:</p><p><a href="${verificationLink}">${verificationLink}</a></p><p>This link will expire in 1 hour.</p>`,
            };

            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.error('Error sending verification email:', error);
                    // Optionally, you might want to delete the user from the database if email sending fails
                    client.query('DELETE FROM users WHERE username = LOWER($1)', [username]).catch(dbErr => {
                        console.error('Error deleting user after email failure:', dbErr);
                    });
                    return res.status(500).json({ error: 'Failed to send verification email. Please try again.' });
                }
                console.log('Verification email sent:', info.response);
                res.status(201).json({ message: 'Registration successful. Please check your email to verify your account.' });
            });

        } catch (err) {
            console.error(`Error registering user ${username} (${email}):`, err);
            // Handle specific database errors (like username or email already exists)
            if (err.code === '23505') { // PostgreSQL unique violation error code
                if (err.constraint === 'users_username_key') {
                    return res.status(400).json({ error: 'Username already exists. Please choose another.' });
                } else if (err.constraint === 'users_email_key') {
                    return res.status(400).json({ error: 'Email address already exists. Please use another.' });
                }
            }
            // Handle generic server errors
            res.status(500).json({ error: 'Internal server error during registration.' });
        }
    });

    // --- Email Verification Route ---
    // Path: GET /api/auth/verify-email
    router.get('/verify-email', async (req, res) => {
        const token = req.query.token;

        if (!token) {
            return res.status(400).json({ error: 'Verification token is missing.' });
        }

        try {
            const result = await client.query(
                'SELECT id, verification_token_expiry FROM users WHERE verification_token = $1',
                [token]
            );

            if (result.rows.length === 0) {
                return res.status(400).json({ error: 'Invalid verification token.' });
            }

            const user = result.rows[0];

            if (new Date(user.verification_token_expiry) < new Date()) {
                // Token has expired, you might want to allow the user to request a new verification email
                await client.query(
                    'UPDATE users SET verification_token = NULL, verification_token_expiry = NULL WHERE id = $1',
                    [user.id]
                );
                return res.status(400).json({ error: 'Verification token has expired. Please request a new one.' });
            }

            // Update user to set email as verified and activate the account
            await client.query(
                'UPDATE users SET email_verified = true, bactive = true, verification_token = NULL, verification_token_expiry = NULL WHERE id = $1',
                [user.id]
            );

            console.log(`Email verified successfully for user ID: ${user.id}`);
            res.status(200).json({ message: 'Email verified successfully. You can now log in.' });
            // Optionally, you can redirect the user to the login page on the frontend
            // res.redirect(`${frontendUrl}/login?verification=success`);

        } catch (err) {
            console.error('Error verifying email:', err);
            res.status(500).json({ error: 'Internal server error during email verification.' });
        }
    });

    // --- Login Route ---
    // Path: POST /api/auth/login (relative to mount point in app.js)
    router.post('/login', async (req, res) => {
        const username = req.body.username?.trim();
        const password = req.body.password;

        // --- Input Validation ---
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required.' });
        }

        try {
            // --- Find User (case-insensitive) ---
            const result = await client.query(
                'SELECT id, username, password, email_verified, bactive FROM users WHERE username = LOWER($1)',
                [username]
            );

            // Check if user exists
            if (result.rows.length === 0) {
                console.log(`Login attempt failed: User not found - ${username}`);
                // Use a generic error message for security (don't reveal if username exists)
                return res.status(401).json({ error: 'Invalid username or password.' });
            }

            const user = result.rows[0]; // Get the user data

            // --- Check if email is verified ---
            if (!user.email_verified) {
                console.log(`Login attempt failed: Email not verified for user - ${username} (${user.id})`);
                return res.status(401).json({ error: 'Please verify your email address before logging in.' });
            }

            // --- Check if account is active ---
            if (!user.bactive) {
                console.log(`Login attempt failed: Account is inactive for user - ${username} (${user.id})`);
                return res.status(403).json({ error: 'Your account is inactive. Please contact support.' });
            }

            // --- Compare Passwords ---
            const isPasswordMatch = await bcrypt.compare(password, user.password);

            if (!isPasswordMatch) {
                console.log(`Login attempt failed: Invalid password for user - ${username}`);
                // Generic error message
                return res.status(401).json({ error: 'Invalid username or password.' });
            }

            // --- Generate JWT ---
            // If passwords match, create a JWT payload
            const payload = {
                userId: user.id,
                username: user.username // Send back the actual stored username casing
                // Add other non-sensitive info if needed (e.g., roles), but keep payload small
            };

            // Sign the token using the secret key and set an expiration time
            const token = jwt.sign(
                payload,
                secretKey,
                { expiresIn: '8h' } // Token valid for 8 hours (adjust as needed)
            );

            console.log(`Login successful: User ${user.id} (${user.username})`);
            // Send the token back to the client
            res.status(200).json({
                token: token,
                userId: user.id, // Optionally send userId and username too
                username: user.username
            });

        } catch (err) {
            console.error(`Login error for user ${username}:`, err);
            // Handle generic server errors
            res.status(500).json({ error: 'Internal server error during login.' });
        }
    });

    // --- Return the configured router ---
    return router;
};