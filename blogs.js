const express = require('express');
const jwt = require('jsonwebtoken');
require('dotenv').config();

// --- Public Logic ---

const getBlogListLogic = (client) => async (req, res) => {
    console.log("Fetching public blog list...");
    try {
        const result = await client.query(`
            SELECT b.id, b.title, LEFT(b.content, 200) AS content_preview, b.created_at, u.username AS author
            FROM blogposts b
            JOIN users u ON b.user_id = u.id
            WHERE b.archived = false
            ORDER BY b.created_at DESC
        `);
        res.status(200).json(result.rows);
    } catch (error) {
        console.error('Error fetching blog posts:', error);
        res.status(500).json({ error: 'Failed to fetch blog posts.' });
    }
};

const getBlogPostByIdLogic = (client) => async (req, res) => {
    const { postId } = req.params;

    if (!/^\d+$/.test(postId)) {
        return res.status(400).json({ error: 'Invalid post ID format.' });
    }

    try {
        const result = await client.query(`
            SELECT b.id, b.title, b.content, b.created_at, u.username AS author
            FROM blogposts b
            JOIN users u ON b.user_id = u.id
            WHERE b.id = $1 AND b.archived = false
        `, [postId]);

        if (result.rows.length > 0) {
            res.status(200).json(result.rows[0]);
        } else {
            res.status(404).json({ error: 'Blog post not found.' });
        }
    } catch (error) {
        console.error('Error fetching blog post:', error);
        res.status(500).json({ error: 'Failed to fetch blog post.' });
    }
};

// --- Public Routes ---
const publicRouterLogic = (client) => {
    const router = express.Router();

    // Get all active (non-archived) blog posts - No authentication required
    router.get('/active', async (req, res) => {
        console.log("Fetching all active blog posts...");
        try {
            const result = await client.query(`
                SELECT b.id, b.title, LEFT(b.content, 200) AS content_preview, b.created_at, u.username AS author
                FROM blogposts b
                JOIN users u ON b.user_id = u.id
                WHERE b.archived = false
                ORDER BY b.created_at DESC
            `);
            res.status(200).json(result.rows);
        } catch (error) {
            console.error('Error fetching active blog posts:', error);
            res.status(500).json({ error: 'Failed to fetch active blog posts.' });
        }
    });

    return router;
};

// --- Protected Routes ---
const protectedRouterLogic = (client) => {
    const router = express.Router();

    const authenticateToken = (req, res, next) => {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        if (!token) return res.sendStatus(401);

        jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
            if (err) return res.sendStatus(403);
            req.user = user;
            next();
        });
    };

    router.use(authenticateToken);

    // GET /me - User's blogs
    router.get('/me', async (req, res) => {
        console.log("Authenticated user payload:", req.user);
        
        const userId = req.user.userId;
        
        if (!userId) {
            return res.status(400).json({ error: 'Invalid or missing user ID in token.' });
        }
        
        console.log(`Fetching blog posts for user ID: ${userId}`);
        try {
            const result = await client.query(`
                SELECT b.id, b.title, LEFT(b.content, 200) AS content_preview, b.created_at
                FROM blogposts b
                WHERE b.user_id = $1
                ORDER BY b.created_at DESC
            `, [userId]);
            res.status(200).json(result.rows);
        } catch (error) {
            console.error(`Error fetching blog posts for user ${userId}:`, error);
            res.status(500).json({ error: 'Failed to fetch your blog posts.' });
        }
    });

    // POST /create - Create a new blog post
    router.post('/create', async (req, res) => {
        const { title, content } = req.body;
        const userId = req.user.id || req.user.userId;

        if (!title || !content) {
            return res.status(400).json({ error: 'Title and content are required.' });
        }

        try {
            const result = await client.query(`
                INSERT INTO blogposts (user_id, title, content)
                VALUES ($1, $2, $3)
                RETURNING *
            `, [userId, title, content]);

            res.status(201).json(result.rows[0]);
        } catch (error) {
            console.error('Error creating blog post:', error);
            res.status(500).json({ error: 'Failed to create blog post.' });
        }
    });

    // PUT /:postId - Edit a blog post
    router.put('/:postId', async (req, res) => {
        const { postId } = req.params;
        const { title, content } = req.body;
        const userId = req.user.id || req.user.userId;

        if (!/^\d+$/.test(postId)) {
            return res.status(400).json({ error: 'Invalid post ID format.' });
        }

        if (!title || !content) {
            return res.status(400).json({ error: 'Title and content are required.' });
        }

        try {
            const result = await client.query(`
                UPDATE blogposts
                SET title = $1, content = $2
                WHERE id = $3 AND user_id = $4 AND archived = false
                RETURNING id, title, content, created_at
            `, [title, content, postId, userId]);

            if (result.rows.length === 0) {
                return res.status(403).json({ error: 'Not authorized or blog post not found.' });
            }

            res.status(200).json({ message: 'Blog post updated successfully.', post: result.rows[0] });
        } catch (error) {
            console.error('Error updating blog post:', error);
            res.status(500).json({ error: 'Failed to update blog post.' });
        }
    });

    // DELETE /:postId - Delete a blog post
    router.delete('/:postId', async (req, res) => {
        const { postId } = req.params;
        const userId = req.user.id || req.user.userId;

        if (!/^\d+$/.test(postId)) {
            return res.status(400).json({ error: 'Invalid post ID format.' });
        }

        try {
            const result = await client.query(`
                DELETE FROM blogposts
                WHERE id = $1 AND user_id = $2
                RETURNING id
            `, [postId, userId]);

            if (result.rowCount > 0) {
                res.status(200).json({ message: 'Blog post deleted successfully.' });
            } else {
                res.status(403).json({ error: 'Not authorized or post not found.' });
            }
        } catch (error) {
            console.error('Error deleting blog post:', error);
            res.status(500).json({ error: 'Failed to delete blog post.' });
        }
    });

    // POST /:postId/archive - Archive a blog post
    router.post('/:postId/archive', async (req, res) => {
        const { postId } = req.params;
        const userId = req.user.id || req.user.userId;

        if (!/^\d+$/.test(postId)) {
            return res.status(400).json({ error: 'Invalid post ID format.' });
        }

        try {
            const result = await client.query(`
                UPDATE blogposts
                SET archived = TRUE
                WHERE id = $1 AND user_id = $2
                RETURNING id
            `, [postId, userId]);

            if (result.rowCount > 0) {
                res.status(200).json({ message: 'Blog post archived successfully.' });
            } else {
                res.status(403).json({ error: 'Not authorized or post not found.' });
            }
        } catch (error) {
            console.error('Error archiving blog post:', error);
            res.status(500).json({ error: 'Failed to archive blog post.' });
        }
    });

    return router;
};

// --- Exports ---
module.exports = (client) => {
    const publicRouter = express.Router();
    
    // Define public routes
    publicRouter.get('/list', getBlogListLogic(client));
    publicRouter.get('/post/:postId', getBlogPostByIdLogic(client)); // Avoids route conflict
    publicRouter.use('/active', publicRouterLogic(client)); // Add active route here

    return {
        public: publicRouter,
        protected: protectedRouterLogic(client)
    };
};
