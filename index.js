import express from "express";
import Stripe from "stripe";
import jwt from "jsonwebtoken";
import cors from "cors";
import dotenv from "dotenv";
import { MongoClient, ServerApiVersion, ObjectId } from "mongodb";

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

import admin from "firebase-admin";
import fs from "fs";

const serviceAccount = JSON.parse(
    fs.readFileSync("./serviceAccountKey.json", "utf8")
);

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
});

async function verifyToken(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    const token = authHeader.split(" ")[1];
    try {
        const decodedToken = await admin.auth().verifyIdToken(token);
        req.user = decodedToken; // contains user's UID, email, etc.
        next();
    } catch (err) {
        console.error("Token verification failed:", err);
        return res.status(401).json({ message: "Invalid token" });
    }
}

// Middleware to check if user is admin
async function verifyAdmin(req, res, next) {
    try {
        if (!req.user?.email) {
            return res.status(401).json({ message: "Unauthorized: No user email found" });
        }

        const email = req.user.email.toLowerCase();
        // fetch user from DB
        const user = await usersCollection.findOne({ email });

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        if (user.role !== "admin") {
            return res.status(403).json({ message: "Forbidden: Admins only" });
        }

        // ✅ user is admin
        next();
    } catch (err) {
        console.error("verifyAdmin error:", err);
        return res.status(500).json({ message: "Server error", error: err.message });
    }
}

async function verifyUser(req, res, next) {
    try {
        if (!req.user?.email) {
            return res.status(401).json({ message: "Unauthorized: No user email found" });
        }

        const email = req.user.email;
        const user = await usersCollection.findOne({ email });

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        if (user.role !== "user") {
            return res.status(403).json({ message: "Forbidden: Only users can access this route" });
        }

        next();
    } catch (err) {
        console.error("verifyUser error:", err);
        res.status(500).json({ message: "Server error", error: err.message });
    }
}

const uri = process.env.MONGO_URI;
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
        tls: true
    },
});

let usersCollection, tagsCollection, postsCollection, commentsCollection, announcementsCollection, paymentsCollection;

async function run() {
    try {

        const db = client.db("myforum");
        usersCollection = db.collection("users");
        tagsCollection = db.collection("tags");
        postsCollection = db.collection("posts");
        commentsCollection = db.collection("comments");
        announcementsCollection = db.collection("announcements");
        paymentsCollection = db.collection("payments");

        app.get("/", (req, res) => res.send("Backend is running!"));

        app.post("/jwt", async (req, res) => {
            const { email } = req.body;
            const user = await usersCollection.findOne({ email });
            if (!user) return res.status(403).json({ message: "User not found" });

            const token = jwt.sign({ email, role: user.role }, process.env.JWT_SECRET, {
                expiresIn: "1h",
            });

            res.json({ token });
        });

        app.post("/users", async (req, res) => {
            try {
                const userData = req.body;

                // Check if user already exists
                const existingUser = await usersCollection.findOne({ email: userData.email });

                if (existingUser) {
                    // ✅ Update avatar or other fields if changed (e.g., from Google login)
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

                // ✅ Insert new user if not exists
                const newUser = {
                    ...userData,
                    role: userData.role || "user",
                    user_status: userData.user_status || "Bronze",
                    membership: userData.membership || "no",
                    posts: userData.posts || 0,
                };

                const result = await usersCollection.insertOne(newUser);
                res.status(201).json({ message: "User registered successfully", userId: result.insertedId });

            } catch (error) {
                console.error("User insert error:", error);
                res.status(500).json({ message: "Internal server error" });
            }
        });

        // GET /users
        app.get("/users", async (req, res) => {
            try {
                const allUsers = await usersCollection.find({}).toArray();
                res.json({ success: true, data: allUsers });
            } catch (err) {
                console.error(err);
                res.status(500).json({ success: false, message: "Server error" });
            }
        });

        // PUT /users/aboutme
        app.put("/users/aboutme", verifyToken, verifyUser, async (req, res) => {
            try {
                const { aboutMe } = req.body;
                const email = req.user?.email?.toLowerCase();

                console.log('email:', email);

                const result = await usersCollection.findOneAndUpdate(
                    { email },
                    { $set: { aboutMe } },
                    { returnDocument: "after" }
                );
                console.log("res value: ", result);
                if (!result) return res.status(404).json({ error: "User not found" });

                res.json({ aboutMe: result.aboutMe });
            } catch (err) {
                console.error("Update About Me error:", err);
                res.status(500).json({ error: "Failed to update About Me" });
            }
        });

        // GET /users/home-stats?email=user@example.com
        app.get("/users/home-stats", verifyToken, verifyUser, async (req, res) => {
            try {
                const email = req.query.email?.toLowerCase();
                if (!email) return res.status(400).json({ error: "Email required" });

                // Use aggregation to calculate stats in one query
                const result = await postsCollection.aggregate([
                    { $match: { authorEmail: email } },
                    {
                        $group: {
                            _id: null,
                            postsCount: { $sum: 1 },
                            totalVotes: {
                                $sum: {
                                    $add: [
                                        { $ifNull: ["$upVote", 0] },
                                        { $ifNull: ["$downVote", 0] }
                                    ]
                                }
                            },
                            commentsCount: {
                                $sum: {
                                    $cond: [
                                        { $isArray: "$comments" },
                                        { $size: "$comments" },
                                        0
                                    ]
                                }
                            }
                        }
                    }
                ]).toArray();

                if (result.length === 0) {
                    return res.json({ posts: 0, comments: 0, votes: 0 });
                }

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

        // PATCH /users/make-admin/:id
        app.patch("/users/make-admin/:id", verifyToken, verifyAdmin, async (req, res) => {
            const { id } = req.params;
            if (!ObjectId.isValid(id)) return res.status(400).json({ success: false, message: "Invalid user ID" });

            try {
                const result = await usersCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { role: "admin" } }
                );

                if (result.modifiedCount === 0) return res.status(404).json({ success: false, message: "User not found" });

                res.json({ success: true, message: "User role updated" });
            } catch (err) {
                console.error(err);
                res.status(500).json({ success: false, message: "Server error" });
            }
        });

        const tags = ["fix", "solve", "bug", "code", "problem", "quick", "crash", "stack", "beautiful", "efficient", "confusing", "branch", "live"];
        const existingTags = await tagsCollection.countDocuments();
        if (existingTags === 0) await tagsCollection.insertMany(tags.map(t => ({ name: t })));

        app.get("/tags", async (req, res) => {
            const allTags = await tagsCollection.find().toArray();
            res.json(allTags);
        });

        app.post("/posts", verifyToken, verifyUser, async (req, res) => {
            try {
                const post = req.body;
                const authorEmail = post.authorEmail?.toLowerCase();

                if (!authorEmail) {
                    return res.status(400).json({ message: "Author email is required" });
                }

                // Insert the post
                const result = await postsCollection.insertOne(post);

                if (result.insertedId) {
                    // Increment the user's post count
                    await usersCollection.updateOne(
                        { email: authorEmail },
                        { $inc: { posts: 1 } }
                    );
                }

                res.status(201).json({
                    message: "Post added successfully",
                    postId: result.insertedId
                });
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

                // Sorting
                cursor = sort === "popularity" ? cursor.sort({ vote: -1 }) : cursor.sort({ creation_time: -1 });

                const totalPosts = await postsCollection.countDocuments();
                const posts = await cursor.skip((pageNumber - 1) * pageSize).limit(pageSize).toArray();

                // Make sure these fields exist for frontend
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

        app.post("/posts/:postId/vote", verifyToken, async (req, res) => {
            try {
                const { postId } = req.params;
                const { type } = req.body;

                // Use email as identifier
                const userEmail = req.user?.email?.toLowerCase();

                console.log("User email:", userEmail);
                console.log("postId:", postId);
                console.log("vote type:", type);

                if (!userEmail) {
                    return res.status(401).json({ error: "User email not found" });
                }

                if (!['upvote', 'downvote'].includes(type)) {
                    return res.status(400).json({ error: "Invalid vote type" });
                }

                const post = await postsCollection.findOne({ _id: new ObjectId(postId) });

                if (!post) {
                    return res.status(404).json({ error: "Post not found" });
                }

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
                } else if (type === 'downvote') {
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
                    {
                        $set: {
                            upVote,
                            downVote,
                            vote,
                            upvote_by,
                            downvote_by
                        }
                    },
                    { returnDocument: "after" }
                );

                if (!result) {
                    return res.status(404).json({ error: "Failed to update post" });
                }

                res.json({
                    upVote,
                    downVote,
                    vote,
                    upvote_by,
                    downvote_by
                });
            } catch (err) {
                console.error("Vote error:", err);
                res.status(500).json({ error: "Failed to process vote", details: err.message });
            }
        });

        // Search posts by tag
        app.post("/posts/search", async (req, res) => {
            try {
                const { tag } = req.body;
                if (!tag || !tag.trim()) {
                    return res.json({ posts: [] });
                }

                const db = client.db("myforum");
                const collection = db.collection("posts");
                const trimmedTag = tag.trim();

                // Search posts where the tag matches (case-insensitive)
                const posts = await collection
                    .find({ tag: { $regex: trimmedTag, $options: "i" } })
                    .toArray();

                res.json({ posts });
            } catch (err) {
                console.error("Search error:", err);
                res.status(500).json({ message: "Failed to search posts" });
            }
        });

        app.get("/posts/:id", verifyToken, async (req, res) => {
            try {
                const { id } = req.params;
                const post = await postsCollection.findOne({ _id: new ObjectId(id) });
                if (!post) return res.status(404).json({ message: "Post not found" });
                res.json(post);
            } catch (err) {
                res.status(500).json({ message: "Failed to fetch post" });
            }
        });

        // 🔹 DELETE /posts/:id
        app.delete("/posts/:id", verifyToken, async (req, res) => {
            const { id } = req.params;
            if (!ObjectId.isValid(id)) {
                return res.status(400).json({ success: false, message: "Invalid post ID" });
            }

            try {
                const result = await postsCollection.deleteOne({ _id: new ObjectId(id) });
                if (result.deletedCount === 0) {
                    return res.status(404).json({ success: false, message: "Post not found" });
                }

                res.json({ success: true, message: "Post deleted successfully" });
            } catch (err) {
                console.error("Error deleting post:", err);
                res.status(500).json({ success: false, message: "Server error" });
            }
        });

        // Add these routes to your existing index.js file

        // POST /comments/:commentId/report - Report a comment
        app.post("/comments/:commentId/report", verifyToken, verifyUser, async (req, res) => {
            try {
                const { commentId } = req.params;
                const { feedback, postId } = req.body;
                const reporterEmail = req.user.email;

                if (!feedback || !postId) {
                    return res.status(400).json({
                        success: false,
                        message: "Feedback and postId are required"
                    });
                }

                // Create reports collection reference
                const db = client.db("myforum");
                const reportsCollection = db.collection("reports");

                // Check if user has already reported this comment
                const existingReport = await reportsCollection.findOne({
                    commentId,
                    reporterEmail
                });

                if (existingReport) {
                    return res.status(400).json({
                        success: false,
                        message: "You have already reported this comment"
                    });
                }

                // Create new report
                const newReport = {
                    commentId,
                    postId,
                    reporterEmail,
                    feedback,
                    reportedAt: new Date(),
                    status: "pending"
                };

                await reportsCollection.insertOne(newReport);

                // Update comment to mark it as reported
                await postsCollection.updateOne(
                    { _id: new ObjectId(postId), "comments._id": new ObjectId(commentId) },
                    {
                        $inc: { "comments.$.reportCount": 1 },
                        $addToSet: { "comments.$.reportedBy": reporterEmail }
                    }
                );

                res.json({
                    success: true,
                    message: "Comment reported successfully",
                    reportId: newReport._id
                });
            } catch (error) {
                console.error("Error reporting comment:", error);
                res.status(500).json({
                    success: false,
                    message: "Failed to report comment"
                });
            }
        });

        app.get("/comments/:commentId/report-status", verifyToken, async (req, res) => {
            try {
                const { commentId } = req.params;
                const userEmail = req.user.email;

                const db = client.db("myforum");
                const reportsCollection = db.collection("reports");

                const report = await reportsCollection.findOne({
                    commentId,
                    reporterEmail: userEmail
                });

                res.json({
                    success: true,
                    hasReported: !!report,
                    reportedAt: report ? report.reportedAt : null
                });
            } catch (error) {
                console.error("Error checking report status:", error);
                res.status(500).json({
                    success: false,
                    message: "Failed to check report status"
                });
            }
        });

        // GET /reports - Get all reports (admin only - you can add admin check middleware)
        app.get("/reports", verifyToken, verifyAdmin, async (req, res) => {
            try {
                const { status, page = 1, limit = 10 } = req.query;
                const pageNumber = parseInt(page);
                const pageSize = parseInt(limit);

                let query = {};
                if (status) {
                    query.status = status;
                }

                const totalReports = await db.collection("reports").countDocuments(query);
                const reports = await db.collection("reports")
                    .find(query)
                    .sort({ reportedAt: -1 })
                    .skip((pageNumber - 1) * pageSize)
                    .limit(pageSize)
                    .toArray();

                res.json({
                    success: true,
                    data: reports,
                    totalReports,
                    totalPages: Math.ceil(totalReports / pageSize),
                    currentPage: pageNumber
                });
            } catch (error) {
                console.error("Error fetching reports:", error);
                res.status(500).json({
                    success: false,
                    message: "Failed to fetch reports"
                });
            }
        });

        // PUT /reports/:reportId/status - Update report status (admin only)
        app.put("/reports/:reportId/status", verifyToken, verifyAdmin, async (req, res) => {
            try {
                const { reportId } = req.params;
                const { status } = req.body;

                if (!["pending", "reviewed", "resolved"].includes(status)) {
                    return res.status(400).json({
                        success: false,
                        message: "Invalid status. Must be: pending, reviewed, or resolved"
                    });
                }

                const result = await db.collection("reports").updateOne(
                    { _id: new ObjectId(reportId) },
                    {
                        $set: {
                            status,
                            updatedAt: new Date(),
                            updatedBy: req.user.email
                        }
                    }
                );

                if (result.matchedCount === 0) {
                    return res.status(404).json({
                        success: false,
                        message: "Report not found"
                    });
                }

                res.json({
                    success: true,
                    message: "Report status updated successfully"
                });
            } catch (error) {
                console.error("Error updating report status:", error);
                res.status(500).json({
                    success: false,
                    message: "Failed to update report status"
                });
            }
        });

        // Assuming Express + MongoDB + verifyToken middleware
        app.post("/posts/:id/vote", verifyToken, async (req, res) => {
            const { type } = req.body;
            const { id } = req.params;
            const email = req.user.email;

            try {
                const post = await postsCollection.findOne({ _id: new ObjectId(id) });
                if (!post) return res.status(404).json({ message: "Post not found" });

                const upvote_by = post.upvote_by || [];
                const downvote_by = post.downvote_by || [];

                if (type === "upvote") {
                    if (!upvote_by.includes(email)) upvote_by.push(email);
                    const index = downvote_by.indexOf(email);
                    if (index !== -1) downvote_by.splice(index, 1);
                } else if (type === "downvote") {
                    if (!downvote_by.includes(email)) downvote_by.push(email);
                    const index = upvote_by.indexOf(email);
                    if (index !== -1) upvote_by.splice(index, 1);
                }

                const updatedPost = await postsCollection.findOneAndUpdate(
                    { _id: new ObjectId(id) },
                    {
                        $set: {
                            upvote_by,
                            downvote_by,
                            upVote: upvote_by.length,
                            downVote: downvote_by.length,
                        },
                    },
                    { returnDocument: "after" } // ensures updated doc is returned
                );

                res.status(200).json(updatedPost.value); // <-- return the updated post
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: "Failed to vote" });
            }
        });

        // POST comment route
        app.post("/posts/:id/comment", verifyToken, async (req, res) => {
            const { id } = req.params;
            const { comment } = req.body; // comment text only
            const userEmail = req.user.email; // verified from Firebase token

            try {
                // 1. Get user data from users collection
                const userData = await usersCollection.findOne({ email: userEmail });
                if (!userData) return res.status(404).json({ message: "User not found" });

                const newComment = {
                    postId: id,
                    postTitle: req.body.postTitle || "",
                    commenterName: userData.fullName || "Anonymous",
                    commenterImage: userData.avatar || null,
                    commenterEmail: userEmail,
                    comment,
                    createdAt: new Date(),
                };

                // 2. Insert into comments collection
                await commentsCollection.insertOne(newComment);

                // 3. Push into post's comments array
                await postsCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $push: { comments: newComment } }
                );

                res.status(201).json(newComment);
            } catch (err) {
                console.error("Comment failed:", err);
                res.status(500).json({ message: "Failed to add comment" });
            }
        });

        app.get("/posts/:id/comments", verifyToken, async (req, res) => {
            const { id } = req.params;
            // Get page and limit from query, default: page 1, limit 5
            const page = parseInt(req.query.page) || 1;
            const limit = parseInt(req.query.limit) || 5;
            const skip = (page - 1) * limit;

            try {
                const totalComments = await commentsCollection.countDocuments({ postId: id });
                const comments = await commentsCollection
                    .find({ postId: id })
                    .sort({ createdAt: -1 })
                    .skip(skip)
                    .limit(limit)
                    .toArray();

                res.json({
                    comments,
                    totalComments
                });
            } catch (err) {
                res.status(500).json({ message: "Failed to fetch comments" });
            }
        });

        // Only authenticated users can add an announcement
        app.post("/announcements", verifyToken, verifyAdmin, async (req, res) => {
            try {
                const { authorName, authorEmail, authorImage, title, description, creation_time } = req.body;

                if (!authorName || !authorEmail || !authorImage || !title || !description)
                    return res.status(400).json({ message: "All fields are required" });

                const newAnnouncement = {
                    authorName,
                    authorEmail,
                    authorImage,
                    title,
                    description,
                    creation_time: creation_time || new Date()
                };

                await announcementsCollection.insertOne(newAnnouncement);
                res.status(201).json(newAnnouncement);
            } catch (err) {
                res.status(500).json({ message: "Failed to add announcement" });
            }
        });

        app.get("/announcements", async (req, res) => {
            try {
                const announcements = await announcementsCollection.find({}).sort({ creation_time: -1 }).toArray();
                res.json(announcements);
            } catch (err) {
                res.status(500).json({ message: "Failed to fetch announcements" });
            }
        });

        app.get("/announcements/count", async (req, res) => {
            try {
                const count = await announcementsCollection.countDocuments();
                res.json({ count });
            } catch (err) {
                res.status(500).json({ message: "Failed to fetch announcement count" });
            }
        });

        // GET user info by email
        // Get user profile and their recent posts
        app.get("/users/profile", verifyToken, verifyUser, async (req, res) => {
            console.log("=== PROFILE ROUTE DEBUG START ===");

            try {
                const email = req.query.email;
                console.log("1. Requested email:", email);
                console.log("2. User from token:", req.user?.email);

                if (!email) {
                    console.log("❌ No email provided");
                    return res.status(400).json({ message: "Email is required" });
                }

                // Check if collections are defined
                console.log("3. Checking collections...");
                console.log("   - usersCollection exists:", !!usersCollection);
                console.log("   - postsCollection exists:", !!postsCollection);

                if (!usersCollection) {
                    console.log("❌ usersCollection is undefined");
                    return res.status(500).json({ message: "Database connection error" });
                }

                console.log("4. Searching for user in database...");
                const user = await usersCollection.findOne({
                    email: email.toLowerCase()
                });

                console.log("5. User query result:", user ? "Found" : "Not found");
                if (user) {
                    console.log("   User details:", {
                        _id: user._id,
                        fullName: user.fullName,
                        email: user.email,
                        role: user.role
                    });
                }

                if (!user) {
                    console.log("❌ User not found for email:", email);
                    return res.status(404).json({ message: "User not found" });
                }

                console.log("6. Searching for user posts...");
                const posts = await postsCollection
                    .find({ authorEmail: email.toLowerCase() })
                    .sort({ creation_time: -1 })
                    .limit(3)
                    .toArray();

                console.log("7. Posts found:", posts.length);

                const totalPosts = await postsCollection.countDocuments({
                    authorEmail: email.toLowerCase()
                });

                console.log("8. Total posts count:", totalPosts);

                const response = {
                    ...user,
                    recentPosts: posts,
                    totalPostCount: totalPosts
                };

                console.log("9. ✅ Sending successful response");
                console.log("=== PROFILE ROUTE DEBUG END ===");

                return res.json(response);

            } catch (err) {
                console.log("=== PROFILE ROUTE ERROR ===");
                console.error("❌ Error type:", err.constructor.name);
                console.error("❌ Error message:", err.message);
                console.error("❌ Error stack:", err.stack);
                console.log("================================");

                return res.status(500).json({
                    message: "Server error",
                    error: err.message,
                    type: err.constructor.name
                });
            }
        });

        app.get("/users/role/:email", verifyToken, async (req, res) => {
            console.log("=== ROLE ROUTE DEBUG ===");
            try {
                const { email } = req.params;
                console.log("Fetching role for:", email);

                if (!usersCollection) {
                    console.log("❌ usersCollection is undefined in role route");
                    return res.status(500).json({ message: "Database connection error" });
                }

                const user = await usersCollection.findOne({
                    email: email.toLowerCase()
                });

                if (!user) {
                    console.log("❌ User not found for role fetch:", email);
                    return res.status(404).json({ message: "User not found" });
                }

                console.log("✅ User role found:", user.role);
                res.json({ role: user.role });

            } catch (error) {
                console.error("❌ Role route error:", error);
                res.status(500).json({ message: "Server error", error: error.message });
            }
        });

        // GET /myposts/:email - Fetch posts for the specified user email
        app.get("/myposts/:email", verifyToken, verifyUser, async (req, res) => {
            try {
                const { email } = req.params;
                const loggedInUserEmail = req.user.email;

                // Check if user is trying to access their own posts
                if (email.toLowerCase() !== loggedInUserEmail.toLowerCase()) {
                    return res.status(403).json({
                        success: false,
                        message: 'You can only access your own posts'
                    });
                }

                // Fetch posts where authorEmail matches the specified email
                const posts = await postsCollection
                    .find({ authorEmail: email.toLowerCase() })
                    .sort({ creation_time: -1 })
                    .toArray();

                // Sanitize posts to ensure all fields exist
                const sanitizedPosts = posts.map(post => ({
                    ...post,
                    upVote: post.upVote || 0,
                    downVote: post.downVote || 0,
                    comments: post.comments || [],
                    upvote_by: post.upvote_by || [],
                    downvote_by: post.downvote_by || []
                }));

                res.json({
                    success: true,
                    data: sanitizedPosts,
                    count: sanitizedPosts.length,
                    userEmail: email
                });
            } catch (error) {
                console.error('Error fetching user posts:', error);
                res.status(500).json({
                    success: false,
                    message: 'Failed to fetch posts'
                });
            }
        });

        app.get("/comments/:id", verifyToken, async (req, res) => {
            try {
                const commentId = req.params.id;

                // Use commentsCollection instead of db.collection("comments")
                const comment = await commentsCollection.findOne({ _id: new ObjectId(commentId) });

                if (!comment) {
                    return res.status(404).json({
                        success: false,
                        message: "Comment not found"
                    });
                }

                res.json({
                    success: true,
                    data: comment
                });
            } catch (err) {
                console.error(err);
                res.status(500).json({
                    success: false,
                    message: "Failed to fetch comment"
                });
            }
        });

        app.delete("/comments/:id", verifyToken, verifyAdmin, async (req, res) => {
            try {
                const commentId = req.params.id;

                // Find the comment to get postId - use commentsCollection
                const comment = await commentsCollection.findOne({ _id: new ObjectId(commentId) });

                if (!comment) {
                    return res.status(404).json({
                        success: false,
                        message: "Comment not found"
                    });
                }

                // Delete comment from comments collection
                await commentsCollection.deleteOne({ _id: new ObjectId(commentId) });

                // Also remove from the post's comments array - use postsCollection
                await postsCollection.updateOne(
                    { _id: new ObjectId(comment.postId) },
                    { $pull: { comments: { _id: new ObjectId(commentId) } } }
                );

                res.json({
                    success: true,
                    message: "Comment deleted successfully"
                });
            } catch (err) {
                console.error(err);
                res.status(500).json({
                    success: false,
                    message: "Failed to delete comment"
                });
            }
        });

        app.delete("/reports/:id", verifyToken, verifyAdmin, async (req, res) => {
            try {
                const reportId = req.params.id;

                const result = await db.collection("reports").deleteOne({ _id: new ObjectId(reportId) });

                if (result.deletedCount === 0) {
                    return res.status(404).json({
                        success: false,
                        message: "Report not found"
                    });
                }

                res.json({
                    success: true,
                    message: "Report deleted successfully"
                });
            } catch (err) {
                console.error(err);
                res.status(500).json({
                    success: false,
                    message: "Failed to delete report"
                });
            }
        });

        // ✅ Create Payment Intent
        app.post("/create-payment-intent", verifyToken, async (req, res) => {
            try {
                const { amount } = req.body;

                const paymentIntent = await stripe.paymentIntents.create({
                    amount,
                    currency: "usd",
                    payment_method_types: ["card"],
                });

                res.send({ clientSecret: paymentIntent.client_secret });
            } catch (error) {
                res.status(500).json({ message: "Stripe error", error: error.message });
            }
        });

        // ✅ Store payment result
        app.post("/save-payment", verifyToken, async (req, res) => {
            try {
                const { email, amount, transactionId, cardType, cardOwner } = req.body;

                if (!email || !transactionId) {
                    return res.status(400).json({ message: "Invalid payment data" });
                }

                // Save transaction
                const paymentRecord = {
                    email,
                    amount,
                    transactionId,
                    cardType,
                    cardOwner,
                    status: "succeeded",
                    createdAt: new Date(),
                };

                await paymentsCollection.insertOne(paymentRecord);

                // Update user to Gold
                const filter = { email: email.toLowerCase() };
                const updateDoc = {
                    $set: {
                        membership: "yes",
                        user_status: "Gold",
                    },
                };
                await usersCollection.updateOne(filter, updateDoc);

                res.status(200).json({ message: "User upgraded to Gold & payment saved" });
            } catch (error) {
                res.status(500).json({ message: "Failed to save payment", error: error.message });
            }
        });

        // Get posts count
        app.get("/api/posts/count", async (req, res) => {
            try {
                const count = await postsCollection.countDocuments();
                res.json({ count });
            } catch (err) {
                console.error(err);
                res.status(500).json({ error: "Failed to get posts count" });
            }
        });

        // Get comments count
        app.get("/api/comments/count", async (req, res) => {
            try {
                const count = await commentsCollection.countDocuments();
                res.json({ count });
            } catch (err) {
                console.error(err);
                res.status(500).json({ error: "Failed to get comments count" });
            }
        });

        // Get users count
        app.get("/api/users/count", async (req, res) => {
            try {
                const count = await usersCollection.countDocuments();
                res.json({ count });
            } catch (err) {
                console.error(err);
                res.status(500).json({ error: "Failed to get users count" });
            }
        });

        // ------------------- Add Tag Route -------------------

        app.post("/addtags", verifyToken, async (req, res) => {
            const { tag } = req.body;
            if (!tag) return res.status(400).json({ error: "Tag is required" });

            try {
                const existingTag = await tagsCollection.findOne({ name: tag });
                if (existingTag) {
                    return res.status(400).json({ error: "Tag already exists" });
                }

                const result = await tagsCollection.insertOne({ name: tag });
                res.json({ message: "Tag added successfully", tagId: result.insertedId });
            } catch (err) {
                console.error(err);
                res.status(500).json({ error: "Failed to add tag" });
            }
        });



    } catch (err) {
        console.error("MongoDB connection failed:", err);
    }
}

run().catch(console.dir);

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});

