require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { MongoClient, ObjectId } = require('mongodb');
const admin = require('firebase-admin');
const Stripe = require('stripe');

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const app = express();
const port = process.env.PORT || 5000;

// -------- Middleware --------
const corsOptions = {
    origin: [
        "http://localhost:5173",
        "https://convonest3.web.app"
    ],
    credentials: true
};

app.use(cors(corsOptions));
app.use(express.json());

// -------- Firebase Admin --------
const serviceAccount = require("./serviceAccountKey.json");

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

// -------- MongoDB Setup --------
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri);
let usersCollection, tagsCollection, postsCollection, commentsCollection, reportsCollection, announcementsCollection, paymentsCollection;

// Connect to MongoDB and start server
async function run() {
    try {
        await client.connect();
        const db = client.db('myforum');

        // Initialize collections
        usersCollection = db.collection('users');
        tagsCollection = db.collection('tags');
        postsCollection = db.collection('posts');
        commentsCollection = db.collection('comments');
        reportsCollection = db.collection('reports');
        announcementsCollection = db.collection('announcements');
        paymentsCollection = db.collection('payments');

        console.log('Connected to MongoDB');

        // -------- Middlewares --------
        const verifyToken = async (req, res, next) => {
            try {
                const authHeader = req.headers.authorization;
                if (!authHeader) return res.status(401).send({ message: "Unauthorized Access" });

                const token = authHeader.split(" ")[1];
                if (!token) return res.status(401).send({ message: "Unauthorized Access" });

                req.decoded = await admin.auth().verifyIdToken(token);
                next();
            } catch (err) {
                return res.status(403).send({ message: "Forbidden Access" });
            }
        };

        const verifyAdmin = async (req, res, next) => {
            try {
                const user = await usersCollection.findOne({ email: req.decoded.email.toLowerCase() });
                if (!user || user.role !== 'admin') return res.status(403).send({ message: "Admin Access Only" });
                next();
            } catch (err) {
                return res.status(500).send({ message: "Server Error" });
            }
        };

        const verifyUser = async (req, res, next) => {
            try {
                const user = await usersCollection.findOne({ email: req.decoded.email.toLowerCase() });
                if (!user) return res.status(404).send({ message: "User Not Found" });
                next();
            } catch (err) {
                return res.status(500).send({ message: "Server Error" });
            }
        };

        // -------- Routes --------
        app.post('/users', async (req, res) => {
            try {
                const { email, fullName, avatar, role = "user", user_status = "Bronze", membership = "no", posts = 0 } = req.body;
                const result = await usersCollection.updateOne(
                    { email: email.toLowerCase() },
                    {
                        $setOnInsert: { email: email.toLowerCase(), role, user_status, membership, posts, createdAt: new Date() },
                        $set: { fullName, avatar, updatedAt: new Date() }
                    },
                    { upsert: true }
                );
                res.json({ success: true, upserted: result.upsertedCount > 0 });
            } catch (err) {
                res.status(500).json({ success: false, message: err.message });
            }
        });

        app.get('/users', async (req, res) => {
            try {
                const { email } = req.query;
                if (email) {
                    const user = await usersCollection.findOne({ email: email.toLowerCase() });
                    return user ? res.json({ success: true, data: [user] }) : res.status(404).json({ error: "User not found" });
                }
                const users = await usersCollection.find().toArray();
                res.json({ success: true, data: users });
            } catch (err) {
                res.status(500).json({ success: false, message: err.message });
            }
        });

        app.get("/users/role/:email", verifyToken, async (req, res) => {

            const user = await usersCollection.findOne({ email: req.params.email.toLowerCase() });
            user ? res.json({ success: true, role: user.role, user_status: user.user_status || "Bronze", membership: user.membership || "no" })
                : res.status(404).json({ error: "User not found" });
        });

        app.get("/users/profile", verifyToken, verifyUser, async (req, res) => {

            const email = req.query.email?.toLowerCase();
            if (!email) return res.status(400).json({ error: "Email required" });

            const user = await usersCollection.findOne({ email });
            if (!user) return res.status(404).json({ error: "User not found" });

            const posts = await postsCollection.find({ authorEmail: email }).sort({ creation_time: -1 }).limit(3).toArray();
            const totalPosts = await postsCollection.countDocuments({ authorEmail: email });

            res.json({ ...user, recentPosts: posts, totalPostCount: totalPosts });
        });

        app.get("/users/home-stats", verifyToken, verifyUser, async (req, res) => {

            const email = req.query.email?.toLowerCase();
            if (!email) return res.status(400).json({ error: "Email required" });

            const result = await postsCollection.aggregate([
                { $match: { authorEmail: email } },
                {
                    $group: {
                        _id: null,
                        postsCount: { $sum: 1 },
                        totalVotes: { $sum: { $add: [{ $ifNull: ["$upVote", 0] }, { $ifNull: ["$downVote", 0] }] } },
                        commentsCount: { $sum: { $cond: [{ $isArray: "$comments" }, { $size: "$comments" }, 0] } }
                    }
                }
            ]).toArray();

            result.length === 0 ? res.json({ posts: 0, comments: 0, votes: 0 })
                : res.json({ posts: result[0].postsCount, comments: result[0].commentsCount, votes: result[0].totalVotes });
        });

        app.put("/users/aboutme", verifyToken, verifyUser, async (req, res) => {

            const { aboutMe } = req.body;
            const result = await usersCollection.findOneAndUpdate(
                { email: req.decoded.email.toLowerCase() },
                { $set: { aboutMe } },
                { returnDocument: "after" }
            );
            result ? res.json({ aboutMe: result.aboutMe }) : res.status(404).json({ error: "User not found" });
        });

        app.patch("/users/make-admin/:id", verifyToken, verifyAdmin, async (req, res) => {

            if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: "Invalid ID" });

            const result = await usersCollection.updateOne(
                { _id: new ObjectId(req.params.id) },
                { $set: { role: "admin" } }
            );
            result.modifiedCount === 0 ? res.status(404).json({ error: "User not found" }) : res.json({ success: true });
        });


        // --- Tags ---
        app.get("/tags", async (req, res) => {

            const tags = await tagsCollection.find().toArray();
            res.json(tags);
        });

        app.post("/addtags", verifyToken, async (req, res) => {

            const { tag } = req.body;
            if (!tag) return res.status(400).json({ error: "Tag required" });

            const existing = await tagsCollection.findOne({ name: tag });
            if (existing) return res.status(400).json({ error: "Tag already exists" });

            const result = await tagsCollection.insertOne({ name: tag });
            res.json({ success: true, insertedId: result.insertedId });
        });

        // --- Posts ---
        app.post("/posts", verifyToken, verifyUser, async (req, res) => {

            const post = { ...req.body, authorEmail: req.body.authorEmail.toLowerCase(), createdAt: new Date() };
            const result = await postsCollection.insertOne(post);

            if (result.insertedId) {
                await usersCollection.updateOne({ email: post.authorEmail }, { $inc: { posts: 1 } });
            }

            res.status(201).json({ success: true, insertedId: result.insertedId });
        });

        app.get("/posts", async (req, res) => {

            const { sort, page = 1, limit = 5 } = req.query;
            const pageNumber = parseInt(page);
            const pageSize = parseInt(limit);

            let cursor = postsCollection.find();
            cursor = sort === "popularity" ? cursor.sort({ vote: -1 }) : cursor.sort({ creation_time: -1 });

            const totalPosts = await postsCollection.countDocuments();
            const posts = await cursor.skip((pageNumber - 1) * pageSize).limit(pageSize).toArray();

            const sanitizedPosts = posts.map(p => ({
                ...p,
                upVote: p.upVote || 0,
                downVote: p.downVote || 0,
                comments: p.comments || [],
                upvote_by: p.upvote_by || [],
                downvote_by: p.downvote_by || []
            }));

            res.json({ totalPosts, totalPages: Math.ceil(totalPosts / pageSize), currentPage: pageNumber, posts: sanitizedPosts });
        });

        app.get("/posts/:id", async (req, res) => {

            if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: "Invalid ID" });

            const post = await postsCollection.findOne({ _id: new ObjectId(req.params.id) });
            post ? res.json(post) : res.status(404).json({ error: "Post not found" });
        });

        app.get("/myposts/:email", verifyToken, verifyUser, async (req, res) => {

            const { email } = req.params;

            if (email.toLowerCase() !== req.decoded.email.toLowerCase()) {
                return res.status(403).json({ error: "Access denied" });
            }

            const posts = await postsCollection.find({ authorEmail: email.toLowerCase() }).sort({ creation_time: -1 }).toArray();
            res.json({ success: true, data: posts, count: posts.length });
        });

        app.post("/posts/search", async (req, res) => {

            const { tag } = req.body;
            if (!tag?.trim()) return res.json({ posts: [] });

            const posts = await postsCollection.find({ tag: { $regex: tag.trim(), $options: "i" } }).toArray();
            res.json({ posts });
        });

        app.delete("/posts/:id", verifyToken, async (req, res) => {

            if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: "Invalid ID" });

            const result = await postsCollection.deleteOne({ _id: new ObjectId(req.params.id) });
            result.deletedCount === 0 ? res.status(404).json({ error: "Post not found" }) : res.json({ success: true });
        });

        app.post("/posts/:postId/vote", verifyToken, async (req, res) => {

            const { postId } = req.params;
            const { type } = req.body;
            const userEmail = req.decoded.email.toLowerCase();

            if (!['upvote', 'downvote'].includes(type)) return res.status(400).json({ error: "Invalid vote type" });

            const post = await postsCollection.findOne({ _id: new ObjectId(postId) });
            if (!post) return res.status(404).json({ error: "Post not found" });

            let upvote_by = post.upvote_by || [];
            let downvote_by = post.downvote_by || [];
            let upVote = post.upVote || 0;
            let downVote = post.downVote || 0;

            const hasUpvoted = upvote_by.includes(userEmail);
            const hasDownvoted = downvote_by.includes(userEmail);

            if (type === 'upvote') {
                if (hasUpvoted) {
                    upvote_by = upvote_by.filter(email => email !== userEmail);
                    upVote = Math.max(0, upVote - 1);
                } else {
                    upvote_by.push(userEmail);
                    upVote += 1;
                    if (hasDownvoted) {
                        downvote_by = downvote_by.filter(email => email !== userEmail);
                        downVote = Math.max(0, downVote - 1);
                    }
                }
            } else {
                if (hasDownvoted) {
                    downvote_by = downvote_by.filter(email => email !== userEmail);
                    downVote = Math.max(0, downVote - 1);
                } else {
                    downvote_by.push(userEmail);
                    downVote += 1;
                    if (hasUpvoted) {
                        upvote_by = upvote_by.filter(email => email !== userEmail);
                        upVote = Math.max(0, upVote - 1);
                    }
                }
            }

            const vote = upVote - downVote;
            const result = await postsCollection.findOneAndUpdate(
                { _id: new ObjectId(postId) },
                { $set: { upVote, downVote, vote, upvote_by, downvote_by } },
                { returnDocument: "after" }
            );

            result ? res.json({ upVote, downVote, vote, upvote_by, downvote_by }) : res.status(404).json({ error: "Update failed" });
        });

        // --- Comments ---
        app.post("/posts/:id/comment", verifyToken, async (req, res) => {

            const { id } = req.params;
            const { comment } = req.body;
            const userEmail = req.decoded.email.toLowerCase();

            const userData = await usersCollection.findOne({ email: userEmail });
            if (!userData) return res.status(404).json({ error: "User not found" });

            const newComment = {
                postId: id,
                postTitle: req.body.postTitle || "",
                commenterName: userData.fullName || "Anonymous",
                commenterImage: userData.avatar || null,
                commenterEmail: userEmail,
                comment,
                createdAt: new Date(),
            };

            await commentsCollection.insertOne(newComment);
            await postsCollection.updateOne({ _id: new ObjectId(id) }, { $push: { comments: newComment } });

            res.status(201).json(newComment);
        });

        app.get("/posts/:id/comments", verifyToken, async (req, res) => {

            const { id } = req.params;
            const page = parseInt(req.query.page) || 1;
            const limit = parseInt(req.query.limit) || 5;
            const skip = (page - 1) * limit;

            const totalComments = await commentsCollection.countDocuments({ postId: id });
            const comments = await commentsCollection.find({ postId: id }).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray();

            res.json({ comments, totalComments });
        });

        app.get("/comments/:id", verifyToken, async (req, res) => {

            if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: "Invalid ID" });

            const comment = await commentsCollection.findOne({ _id: new ObjectId(req.params.id) });
            comment ? res.json({ success: true, data: comment }) : res.status(404).json({ error: "Comment not found" });
        });

        app.delete("/comments/:id", verifyToken, verifyAdmin, async (req, res) => {

            if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: "Invalid ID" });

            const comment = await commentsCollection.findOne({ _id: new ObjectId(req.params.id) });
            if (!comment) return res.status(404).json({ error: "Comment not found" });

            await commentsCollection.deleteOne({ _id: new ObjectId(req.params.id) });
            await postsCollection.updateOne({ _id: new ObjectId(comment.postId) }, { $pull: { comments: { _id: new ObjectId(req.params.id) } } });

            res.json({ success: true });
        });

        // --- Reports ---
        app.post("/comments/:commentId/report", verifyToken, verifyUser, async (req, res) => {

            const { commentId } = req.params;
            const { feedback, postId } = req.body;
            const reporterEmail = req.decoded.email.toLowerCase();

            if (!feedback || !postId) return res.status(400).json({ error: "Feedback and postId required" });

            const existing = await reportsCollection.findOne({ commentId, reporterEmail });
            if (existing) return res.status(400).json({ error: "Already reported" });

            const newReport = { commentId, postId, reporterEmail, feedback, reportedAt: new Date(), status: "pending" };
            const result = await reportsCollection.insertOne(newReport);

            await postsCollection.updateOne(
                { _id: new ObjectId(postId), "comments._id": new ObjectId(commentId) },
                { $inc: { "comments.$.reportCount": 1 }, $addToSet: { "comments.$.reportedBy": reporterEmail } }
            );

            res.json({ success: true, insertedId: result.insertedId });
        });

        app.get("/comments/:commentId/report-status", verifyToken, async (req, res) => {

            const report = await reportsCollection.findOne({ commentId: req.params.commentId, reporterEmail: req.decoded.email.toLowerCase() });
            res.json({ success: true, hasReported: !!report, reportedAt: report?.reportedAt || null });
        });

        app.get("/reports", verifyToken, verifyUser, async (req, res) => {

            const { page = 1, limit = 10 } = req.query;
            const pageNumber = parseInt(page);
            const pageSize = parseInt(limit);

            const query = { reporterEmail: req.decoded.email.toLowerCase() };
            const totalReports = await reportsCollection.countDocuments(query);
            const reports = await reportsCollection.find(query).sort({ reportedAt: -1 }).skip((pageNumber - 1) * pageSize).limit(pageSize).toArray();

            res.json({ success: true, data: reports, totalReports, totalPages: Math.ceil(totalReports / pageSize), currentPage: pageNumber });
        });

        app.get("/reportsforadmin", verifyToken, verifyAdmin, async (req, res) => {

            const { page = 1, limit = 10, status = "pending" } = req.query;
            const pageNumber = parseInt(page);
            const pageSize = parseInt(limit);

            const query = { status };
            const totalReports = await reportsCollection.countDocuments(query);
            const reports = await reportsCollection.find(query).sort({ reportedAt: -1 }).skip((pageNumber - 1) * pageSize).limit(pageSize).toArray();

            res.json({ success: true, data: reports, totalReports, totalPages: Math.ceil(totalReports / pageSize), currentPage: pageNumber });
        });

        app.put("/reports/:reportId/status", verifyToken, verifyAdmin, async (req, res) => {

            const { status } = req.body;

            if (!["pending", "reviewed", "resolved"].includes(status)) {
                return res.status(400).json({ error: "Invalid status" });
            }

            const result = await reportsCollection.updateOne(
                { _id: new ObjectId(req.params.reportId) },
                { $set: { status, updatedAt: new Date(), updatedBy: req.decoded.email.toLowerCase() } }
            );

            result.matchedCount === 0 ? res.status(404).json({ error: "Report not found" }) : res.json({ success: true });
        });

        app.delete("/reports/:id", verifyToken, verifyAdmin, async (req, res) => {

            if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: "Invalid ID" });

            const result = await reportsCollection.deleteOne({ _id: new ObjectId(req.params.id) });
            result.deletedCount === 0 ? res.status(404).json({ error: "Report not found" }) : res.json({ success: true });
        });

        // --- Announcements ---
        app.post("/announcements", verifyToken, verifyAdmin, async (req, res) => {

            const { authorName, authorEmail, authorImage, title, description } = req.body;

            if (!authorName || !authorEmail || !title || !description) {
                return res.status(400).json({ error: "Missing required fields" });
            }

            const announcement = { authorName, authorEmail, authorImage, title, description, creation_time: new Date() };
            const result = await announcementsCollection.insertOne(announcement);
            res.status(201).json({ success: true, insertedId: result.insertedId });
        });

        app.get("/announcements", async (req, res) => {

            const announcements = await announcementsCollection.find().sort({ creation_time: -1 }).toArray();
            res.json(announcements);
        });

        app.get("/announcements/count", async (req, res) => {

            const count = await announcementsCollection.countDocuments();
            res.json({ count });
        });

        // --- Payments ---
        app.post("/create-payment-intent", async (req, res) => {
            const { amount } = req.body;
            const paymentIntent = await stripe.paymentIntents.create({
                amount: Math.round(amount * 100),
                currency: "usd",
                automatic_payment_methods: { enabled: true }
            });
            res.json({ clientSecret: paymentIntent.client_secret });
        });

        app.post("/save-payment", async (req, res) => {

            const { email, amount, transactionId, cardType, cardOwner } = req.body;

            if (!email || !transactionId) return res.status(400).json({ error: "Invalid payment data" });

            const payment = { email: email.toLowerCase(), amount, transactionId, cardType, cardOwner, status: "succeeded", createdAt: new Date() };
            await paymentsCollection.insertOne(payment);

            await usersCollection.updateOne(
                { email: email.toLowerCase() },
                { $set: { membership: "yes", user_status: "Gold" } }
            );

            res.json({ success: true });
        });

        // --- Stats ---
        app.get("/api/posts/count", async (req, res) => {

            const count = await postsCollection.countDocuments();
            res.json({ count });
        });

        app.get("/api/comments/count", async (req, res) => {

            const count = await commentsCollection.countDocuments();
            res.json({ count });
        });

        app.get("/api/users/count", async (req, res) => {

            const count = await usersCollection.countDocuments();
            res.json({ count });
        });


    } catch (err) {
        console.error('MongoDB connection failed:', err);
        process.exit(1);
    }
}

run();



// Default route
app.get('/', (req, res) => {
    res.send('Food Zone Server Running properly');
});

// Start server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});