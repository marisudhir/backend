const express = require('express');
const router = express.Router();
const nodemailer = require('nodemailer');

// Helper function to send email
async function sendEmail(config, mailOptions) {
    try {
        const transporter = nodemailer.createTransport(config);
        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent:', info);
        return true;
    } catch (error) {
        console.error('Error sending email:', error);
        return false;
    }
}

module.exports = (client, FRONTEND_ORIGIN, emailConfig) => {
    // Endpoint to subscribe to an author's posts
    router.post('/subscribe/:userId', async (req, res) => {
        const { userId } = req.params;
        const { email } = req.body;

        if (!/^\d+$/.test(userId)) {
            return res.status(400).json({ error: 'Invalid user ID format.' });
        }
        if (!email || !/\S+@\S+\.\S+/.test(email)) {
            return res.status(400).json({ error: 'Invalid email format.' });
        }

        try {
            const existingSubscription = await client.query(
                `SELECT 1 FROM subscriptions WHERE user_id = $1 AND email = $2 AND active = TRUE`,
                [userId, email]
            );
            if (existingSubscription.rowCount > 0) {
                return res.status(200).json({ message: 'Already subscribed.' });
            }

            await client.query(
                `INSERT INTO subscriptions (user_id, email, subscribed_at, active) VALUES ($1, $2, NOW(), TRUE)`,
                [userId, email]
            );
            res.status(201).json({ message: 'Subscribed successfully.' });

        } catch (err) {
            console.error('Error subscribing:', err);
            res.status(500).json({ error: 'Failed to subscribe.' });
        }
    });

    // Endpoint to unsubscribe from an author's posts
    router.get('/unsubscribe', async (req, res) => {
        const { userId, email } = req.query;

        if (!userId || !email) {
            return res.status(400).json({ error: 'User ID and email are required to unsubscribe.' });
        }

        try {
            const result = await client.query(
                `UPDATE subscriptions SET active = FALSE WHERE user_id = $1 AND email = $2 RETURNING *`,
                [userId, email]
            );

            if (result.rowCount > 0) {
                return res.status(200).send('You have been successfully unsubscribed.');
            } else {
                return res.status(404).send('Subscription not found.');
            }
        } catch (err) {
            console.error('Error unsubscribing:', err);
            return res.status(500).json({ error: 'Failed to unsubscribe.' });
        }
    });

    // Function to notify subscribers (exported for use in blog routes)
    const notifySubscribers = async (userId, post) => {
        try {
            const authorResult = await client.query(
                `SELECT full_name FROM users WHERE id = $1`,
                [userId]
            );

            if (authorResult.rows.length > 0) {
                const authorName = authorResult.rows[0].full_name;
                const subscribers = await client.query(
                    `SELECT email FROM subscriptions WHERE user_id = $1 AND active = TRUE`,
                    [userId]
                );
                if (subscribers.rows.length > 0) {
                    // Create an array to store promises for sending emails
                    const emailPromises = subscribers.rows.map(async (subscriber) => {
                        const unsubscribeLink = `${FRONTEND_ORIGIN}/unsubscribe?userId=${userId}&email=${encodeURIComponent(subscriber.email)}`;
                        const mailOptions = {
                            from: process.env.EMAIL_USER,
                            to: subscriber.email,
                            subject: `New Post from ${authorName}: ${post.title}`,
                            html: `<p>A new blog post "${post.title}" has been published by ${authorName}. Read it here: <a href="${FRONTEND_ORIGIN}/blog/${post.id}">${FRONTEND_ORIGIN}/blog/${post.id}</a></p>
                                   <hr>
                                   <p style="font-size: 0.8em; color: #777;">
                                       To unsubscribe from receiving these updates, click here:
                                       <a href="${unsubscribeLink}">Unsubscribe</a>
                                   </p>`,
                        };
                        return sendEmail(emailConfig, mailOptions);
                    });

                    // Wait for all emails to be sent
                    await Promise.all(emailPromises);
                }
            } else {
                console.error(`Author with ID ${userId} not found.`);
            }
        } catch (err) {
            console.error('Error notifying subscribers:', err);
        }
    };

    return { router, notifySubscribers };
};