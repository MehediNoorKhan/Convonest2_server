import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { MongoClient, ServerApiVersion, ObjectId } from "mongodb";

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

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


const uri = process.env.MONGO_URI;
const client = new MongoClient(uri, {
    serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true, tls: true },
});

let usersCollection, tagsCollection, postsCollection, commentsCollection, announcementsCollection;

async function run() {
    try {
        await client.connect();
        console.log("MongoDB connected successfully!");

        const db = client.db("myforum");
        usersCollection = db.collection("users");
        tagsCollection = db.collection("tags");
        postsCollection = db.collection("posts");
        commentsCollection = db.collection("comments");
        announcementsCollection = db.collection("announcements");


        app.get("/", (req, res) => res.send("Backend is running!"));

        // app.get("/users", async (req, res) => {
        //     const users = await usersCollection.find().toArray();
        //     res.json(users);
        // });

        app.post("/users", async (req, res) => {
            try {
                const userData = req.body;
                const existingUser = await usersCollection.findOne({ email: userData.email });
                if (existingUser) return res.status(400).json({ message: "Email already registered" });

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


        // PATCH /users/make-admin/:id
        app.patch("/users/make-admin/:id", async (req, res) => {
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

        app.post("/posts", async (req, res) => {
            try {
                const post = req.body;
                const result = await postsCollection.insertOne(post);
                res.status(201).json({ message: "Post added successfully", postId: result.insertedId });
            } catch (err) {
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


        app.get("/posts/:id", async (req, res) => {
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
        app.delete("/posts/:id", async (req, res) => {
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
        app.post("/comments/:commentId/report", verifyToken, async (req, res) => {
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

                // Check if user has already reported this comment
                const existingReport = await db.collection("reports").findOne({
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
                    status: "pending" // pending, reviewed, resolved
                };

                await db.collection("reports").insertOne(newReport);

                // Optional: Update comment to mark it as reported
                await postsCollection.updateOne(
                    {
                        _id: new ObjectId(postId),
                        "comments._id": new ObjectId(commentId)
                    },
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

        // GET /comments/:commentId/report-status - Check if user has reported this comment
        app.get("/comments/:commentId/report-status", verifyToken, async (req, res) => {
            try {
                const { commentId } = req.params;
                const userEmail = req.user.email;

                const report = await db.collection("reports").findOne({
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
        app.get("/reports", verifyToken, async (req, res) => {
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
        app.put("/reports/:reportId/status", verifyToken, async (req, res) => {
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


        app.get("/posts/:id/comments", async (req, res) => {
            const { id } = req.params;
            try {
                const comments = await commentsCollection.find({ postId: id }).sort({ createdAt: -1 }).toArray();
                res.json(comments);
            } catch (err) {
                res.status(500).json({ message: "Failed to fetch comments" });
            }
        });



        // Only authenticated users can add an announcement
        app.post("/announcements", verifyToken, async (req, res) => {
            try {
                const { authorName, authorEmail, authorImage, title, description, creation_time } = req.body;
                if (!authorName || !authorEmail || !authorImage || !title || !description)
                    return res.status(400).json({ message: "All fields are required" });

                const newAnnouncement = { authorName, authorEmail, authorImage, title, description, creation_time: creation_time || new Date() };
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
        app.get("/users/profile", verifyToken, async (req, res) => {
            try {
                const email = req.query.email;
                if (!email) {
                    return res.status(400).json({ message: "Email is required" });
                }

                // find user
                const user = await db.collection("users").findOne({ email: email.toLowerCase() });
                if (!user) {
                    return res.status(404).json({ message: "User not found" });
                }

                // find 3 most recent posts of that user
                const posts = await db
                    .collection("posts")
                    .find({ authorEmail: email.toLowerCase() })
                    .sort({ creation_time: -1 }) // newest first
                    .limit(3)
                    .toArray();

                return res.json({
                    ...user,
                    recentPosts: posts,
                });
            } catch (err) {
                console.error("Error fetching profile:", err);
                return res.status(500).json({ message: "Server error" });
            }
        });

        // Add this route to your existing index.js file after the other routes

        // GET /myposts/:email - Fetch posts for the specified user email
        app.get("/myposts/:email", verifyToken, async (req, res) => {
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
                    .sort({ creation_time: -1 }) // Sort by newest first
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
                const comment = await db.collection("comments").findOne({ _id: new ObjectId(commentId) });

                if (!comment) {
                    return res.status(404).json({ success: false, message: "Comment not found" });
                }

                res.json({ success: true, data: comment });
            } catch (err) {
                console.error(err);
                res.status(500).json({ success: false, message: "Failed to fetch comment" });
            }
        });

        app.delete("/comments/:id", verifyToken, async (req, res) => {
            try {
                const commentId = req.params.id;

                // Find the comment to get postId
                const comment = await db.collection("comments").findOne({ _id: new ObjectId(commentId) });
                if (!comment) {
                    return res.status(404).json({ success: false, message: "Comment not found" });
                }

                // Delete comment from comments collection
                await db.collection("comments").deleteOne({ _id: new ObjectId(commentId) });

                // Also remove from the post's comments array
                await db.collection("posts").updateOne(
                    { _id: new ObjectId(comment.postId) },
                    { $pull: { comments: { _id: new ObjectId(commentId) } } }
                );

                res.json({ success: true, message: "Comment deleted successfully" });
            } catch (err) {
                console.error(err);
                res.status(500).json({ success: false, message: "Failed to delete comment" });
            }
        });


        app.delete("/reports/:id", verifyToken, async (req, res) => {
            try {
                const reportId = req.params.id;
                const result = await db.collection("reports").deleteOne({ _id: new ObjectId(reportId) });

                if (result.deletedCount === 0) {
                    return res.status(404).json({ success: false, message: "Report not found" });
                }

                res.json({ success: true, message: "Report deleted successfully" });
            } catch (err) {
                console.error(err);
                res.status(500).json({ success: false, message: "Failed to delete report" });
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
