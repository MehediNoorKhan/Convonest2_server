import dotenv from "dotenv";
dotenv.config();

import express from "express";
import Stripe from "stripe";
import jwt from "jsonwebtoken";
import cors from "cors";
import admin from "firebase-admin";
import { MongoClient, ServerApiVersion, ObjectId } from "mongodb";

const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// Initialize Firebase Admin SDK
const decodedKey = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf8');
const serviceAccount = JSON.parse(decodedKey);

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
});

// MongoDB connection
const client = new MongoClient(process.env.MONGO_URI, {
    serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true, tls: true }
});

let usersCollection, tagsCollection, postsCollection, commentsCollection, announcementsCollection, paymentsCollection;

// ---------------- Middleware ----------------

// Verify Firebase token
async function verifyToken(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) return res.status(401).json({ message: "Unauthorized" });

    const token = authHeader.split(" ")[1];
    try {
        const decodedToken = await admin.auth().verifyIdToken(token);
        req.user = decodedToken;
        next();
    } catch (err) {
        console.error("Token verification failed:", err);
        return res.status(401).json({ message: "Invalid token" });
    }
}

// Check admin role
async function verifyAdmin(req, res, next) {
    try {
        const email = req.user?.email?.toLowerCase();
        if (!email) return res.status(401).json({ message: "Unauthorized: No user email found" });

        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(404).json({ message: "User not found" });
        if (user.role !== "admin") return res.status(403).json({ message: "Forbidden: Admins only" });

        next();
    } catch (err) {
        console.error("verifyAdmin error:", err);
        res.status(500).json({ message: "Server error", error: err.message });
    }
}

// Check regular user role
async function verifyUser(req, res, next) {
    try {
        const email = req.user?.email?.toLowerCase();
        if (!email) return res.status(401).json({ message: "Unauthorized: No user email found" });

        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(404).json({ message: "User not found" });
        if (user.role !== "user") return res.status(403).json({ message: "Forbidden: Only users can access this route" });

        next();
    } catch (err) {
        console.error("verifyUser error:", err);
        res.status(500).json({ message: "Server error", error: err.message });
    }
}

// ------------------- MongoDB Setup -------------------
async function run() {
    try {
        const db = client.db("myforum");

        usersCollection = db.collection("users");
        tagsCollection = db.collection("tags");
        postsCollection = db.collection("posts");
        commentsCollection = db.collection("comments");
        announcementsCollection = db.collection("announcements");
        paymentsCollection = db.collection("payments");

        console.log("MongoDB connected successfully");

        // ------------------- Routes -------------------

        // Health check
        app.get("/", (req, res) => res.send("Backend is running!"));

        // ------------------- JWT -------------------
        app.post("/jwt", async (req, res) => {
            try {
                const { email } = req.body;
                if (!email) return res.status(400).json({ message: "Email missing" });

                const user = await usersCollection.findOne({ email });
                if (!user) return res.status(403).json({ message: "User not found" });

                const token = jwt.sign({ email, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1h" });
                res.json({ token });
            } catch (err) {
                console.error("JWT generation error:", err);
                res.status(500).json({ message: "Internal Server Error" });
            }
        });

        // ------------------- Users -------------------

        // Create or update user
        app.post("/users", async (req, res) => {
            try {
                const userData = req.body;
                const existingUser = await usersCollection.findOne({ email: userData.email });

                if (existingUser) {
                    const updatedUser = {
                        $set: {
                            fullName: userData.fullName || existingUser.fullName,
                            avatar: userData.avatar || existingUser.avatar,
                            user_status: existingUser.user_status || "Bronze",
                            membership: existingUser.membership || "no",
                            posts: existingUser.posts || 0,
                            role: existingUser.role || "user",
                        },
                    };
                    await usersCollection.updateOne({ email: userData.email }, updatedUser);
                    return res.status(200).json({ message: "User already existed, updated successfully" });
                }

                const newUser = {
                    ...userData,
                    role: userData.role || "user",
                    user_status: userData.user_status || "Bronze",
                    membership: userData.membership || "no",
                    posts: userData.posts || 0,
                };
                const result = await usersCollection.insertOne(newUser);
                res.status(201).json({ message: "User registered successfully", userId: result.insertedId });
            } catch (err) {
                console.error("User insert error:", err);
                res.status(500).json({ message: "Internal server error" });
            }
        });

        // Get users (all or by email)
        app.get("/users", async (req, res) => {
            try {
                const { email } = req.query;
                let users;

                if (email) {
                    const user = await usersCollection.findOne({ email });
                    if (!user) return res.status(404).json({ success: false, message: "User not found" });
                    users = [user];
                } else {
                    users = await usersCollection.find({}).toArray();
                }

                res.json({ success: true, data: users });
            } catch (err) {
                console.error(err);
                res.status(500).json({ success: false, message: "Server error" });
            }
        });

        // Update user's About Me
        app.put("/users/aboutme", verifyToken, verifyUser, async (req, res) => {
            try {
                const { aboutMe } = req.body;
                const email = req.user.email.toLowerCase();

                const result = await usersCollection.findOneAndUpdate(
                    { email },
                    { $set: { aboutMe } },
                    { returnDocument: "after" }
                );

                if (!result) return res.status(404).json({ error: "User not found" });

                res.json({ aboutMe: result.aboutMe });
            } catch (err) {
                console.error("Update About Me error:", err);
                res.status(500).json({ error: "Failed to update About Me" });
            }
        });

        // Get user's stats for homepage
        app.get("/users/home-stats", verifyToken, verifyUser, async (req, res) => {
            try {
                const email = req.query.email?.toLowerCase();
                if (!email) return res.status(400).json({ error: "Email required" });

                const result = await postsCollection.aggregate([
                    { $match: { authorEmail: email } },
                    {
                        $group: {
                            _id: null,
                            postsCount: { $sum: 1 },
                            totalVotes: {
                                $sum: {
                                    $add: [{ $ifNull: ["$upVote", 0] }, { $ifNull: ["$downVote", 0] }]
                                }
                            },
                            commentsCount: { $sum: { $cond: [{ $isArray: "$comments" }, { $size: "$comments" }, 0] } }
                        }
                    }
                ]).toArray();

                if (!result.length) return res.json({ posts: 0, comments: 0, votes: 0 });

                res.json({
                    posts: result[0].postsCount,
                    comments: result[0].commentsCount,
                    votes: result[0].totalVotes
                });
            } catch (err) {
                console.error("Failed to fetch user home stats:", err);
                res.status(500).json({ error: "Failed to fetch stats" });
            }
        });

        // Promote user to admin
        app.patch("/users/make-admin/:id", verifyToken, verifyAdmin, async (req, res) => {
            const { id } = req.params;
            if (!ObjectId.isValid(id)) return res.status(400).json({ success: false, message: "Invalid user ID" });

            try {
                const result = await usersCollection.updateOne({ _id: new ObjectId(id) }, { $set: { role: "admin" } });
                if (!result.modifiedCount) return res.status(404).json({ success: false, message: "User not found" });

                res.json({ success: true, message: "User role updated" });
            } catch (err) {
                console.error(err);
                res.status(500).json({ success: false, message: "Server error" });
            }
        });

        // ------------------- Tags -------------------
        const defaultTags = ["fix", "solve", "bug", "code", "problem", "quick", "crash", "stack", "beautiful", "efficient", "confusing", "branch", "live"];
        const existingTags = await tagsCollection.countDocuments();
        if (!existingTags) await tagsCollection.insertMany(defaultTags.map(t => ({ name: t })));

        app.get("/tags", async (req, res) => {
            const tags = await tagsCollection.find().toArray();
            res.json(tags);
        });

        app.post("/addtags", verifyToken, async (req, res) => {
            const { tag } = req.body;
            if (!tag) return res.status(400).json({ error: "Tag is required" });

            try {
                const exists = await tagsCollection.findOne({ name: tag });
                if (exists) return res.status(400).json({ error: "Tag already exists" });

                const result = await tagsCollection.insertOne({ name: tag });
                res.json({ message: "Tag added successfully", tagId: result.insertedId });
            } catch (err) {
                console.error(err);
                res.status(500).json({ error: "Failed to add tag" });
            }
        });

        // ------------------- Posts -------------------
        app.post("/posts", verifyToken, verifyUser, async (req, res) => {
            try {
                const post = req.body;
                const authorEmail = post.authorEmail?.toLowerCase();
                if (!authorEmail) return res.status(400).json({ message: "Author email is required" });

                const result = await postsCollection.insertOne(post);
                if (result.insertedId) await usersCollection.updateOne({ email: authorEmail }, { $inc: { posts: 1 } });

                res.status(201).json({ message: "Post added successfully", postId: result.insertedId });
            } catch (err) {
                console.error("Failed to add post:", err);
                res.status(500).json({ message: "Failed to add post" });
            }
        });

        app.get("/posts", async (req, res) => {
            try {
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

                res.json({
                    totalPosts,
                    totalPages: Math.ceil(totalPosts / pageSize),
                    currentPage: pageNumber,
                    posts: sanitizedPosts
                });
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: "Failed to fetch posts" });
            }
        });

        // ------------------- Voting -------------------
        // Upvote a post
        app.post("/posts/:id/upvote", verifyToken, verifyUser, async (req, res) => {
            try {
                const { id } = req.params;
                const email = req.user.email.toLowerCase();

                const post = await postsCollection.findOne({ _id: new ObjectId(id) });
                if (!post) return res.status(404).json({ message: "Post not found" });

                // Prevent duplicate upvote
                if (post.upvote_by?.includes(email)) return res.status(400).json({ message: "Already upvoted" });

                await postsCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $inc: { upVote: 1 }, $push: { upvote_by: email } }
                );

                res.json({ message: "Post upvoted successfully" });
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: "Failed to upvote" });
            }
        });

        // Downvote a post
        app.post("/posts/:id/downvote", verifyToken, verifyUser, async (req, res) => {
            try {
                const { id } = req.params;
                const email = req.user.email.toLowerCase();

                const post = await postsCollection.findOne({ _id: new ObjectId(id) });
                if (!post) return res.status(404).json({ message: "Post not found" });

                if (post.downvote_by?.includes(email)) return res.status(400).json({ message: "Already downvoted" });

                await postsCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $inc: { downVote: 1 }, $push: { downvote_by: email } }
                );

                res.json({ message: "Post downvoted successfully" });
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: "Failed to downvote" });
            }
        });

        // ------------------- Comments -------------------
        // Add a comment to a post
        app.post("/posts/:id/comments", verifyToken, verifyUser, async (req, res) => {
            try {
                const { id } = req.params;
                const { text } = req.body;
                const email = req.user.email.toLowerCase();

                if (!text) return res.status(400).json({ message: "Comment text required" });

                const comment = {
                    text,
                    authorEmail: email,
                    createdAt: new Date()
                };

                await postsCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $push: { comments: comment } }
                );

                res.json({ message: "Comment added successfully" });
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: "Failed to add comment" });
            }
        });

        // ------------------- Reports -------------------
        // Report a comment
        app.post("/comments/:id/report", verifyToken, verifyUser, async (req, res) => {
            try {
                const { id } = req.params;
                const { feedback } = req.body;
                const reporterEmail = req.user.email.toLowerCase();

                const reportedComment = await commentsCollection.findOne({ _id: new ObjectId(id) });
                if (!reportedComment) return res.status(404).json({ message: "Comment not found" });

                const report = {
                    commentId: id,
                    reporterEmail,
                    feedback,
                    reportedAt: new Date()
                };

                await commentsCollection.insertOne(report);
                res.json({ message: "Comment reported successfully" });
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: "Failed to report comment" });
            }
        });

        // ------------------- Announcements -------------------
        app.get("/announcements", async (req, res) => {
            try {
                const announcements = await announcementsCollection.find().sort({ createdAt: -1 }).toArray();
                res.json(announcements);
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: "Failed to fetch announcements" });
            }
        });

        app.post("/announcements", verifyToken, verifyAdmin, async (req, res) => {
            try {
                const announcement = { ...req.body, createdAt: new Date() };
                const result = await announcementsCollection.insertOne(announcement);
                res.status(201).json({ message: "Announcement created", id: result.insertedId });
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: "Failed to create announcement" });
            }
        });

        // ------------------- Stripe Payments -------------------
        app.post("/create-payment-intent", verifyToken, async (req, res) => {
            try {
                const { amount, currency = "usd" } = req.body;
                if (!amount) return res.status(400).json({ message: "Amount is required" });

                const paymentIntent = await stripe.paymentIntents.create({
                    amount,
                    currency,
                    payment_method_types: ["card"]
                });

                res.json({ clientSecret: paymentIntent.client_secret });
            } catch (err) {
                console.error("Stripe error:", err);
                res.status(500).json({ message: "Failed to create payment intent" });
            }
        });


    } catch (err) {
        console.error("MongoDB connection failed:", err);
    }
}

run().catch(console.dir);

app.listen(port, () => console.log(`Server running on http://localhost:${port}`));
