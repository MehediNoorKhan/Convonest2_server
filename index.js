import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { MongoClient, ServerApiVersion, ObjectId } from "mongodb";
import admin from "firebase-admin";
import Stripe from "stripe";

// ---------- Environment ----------
const { MONGO_URI, STRIPE_SECRET_KEY, FB_SERVICE_KEY } = process.env;

if (!MONGO_URI) throw new Error("MONGO_URI is missing");
if (!STRIPE_SECRET_KEY) throw new Error("STRIPE_SECRET_KEY is missing");
if (!FB_SERVICE_KEY) throw new Error("FB_SERVICE_KEY is missing");

// ---------- Firebase Admin ----------
let serviceAccount;
try {
    serviceAccount = JSON.parse(Buffer.from(FB_SERVICE_KEY, "base64").toString("utf8"));
} catch (err) {
    console.error("Invalid Firebase Key", err);
    throw new Error("FB_SERVICE_KEY is invalid");
}

if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
    });
    console.log("✅ Firebase Admin Initialized");
}

// ---------- Stripe ----------
const stripe = new Stripe(STRIPE_SECRET_KEY);

// ---------- Express ----------
const app = express();
app.use(helmet());

// ---------- CORS ----------
const allowedOrigins = [
    "http://localhost:5173",
    "https://your-vercel-frontend.vercel.app",
];
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
        callback(new Error("Not allowed by CORS"));
    },
    credentials: true
}));

app.use(express.json({ limit: "10mb" }));
app.use(rateLimit({ windowMs: 60 * 1000, max: 120 }));

// ---------- MongoDB Lazy Connection ----------
let cachedClient = global._mongoClient;
let cachedDb = global._mongoDb;

async function connectDB() {
    if (cachedClient && cachedDb) return { client: cachedClient, db: cachedDb };

    const client = new MongoClient(MONGO_URI, {
        serverApi: { version: ServerApiVersion.v1, strict: true }
    });
    await client.connect();
    const db = client.db("myforum");

    cachedClient = client;
    cachedDb = db;
    global._mongoClient = client;
    global._mongoDb = db;

    return { client, db };
}

// ---------- Firebase Token Middleware ----------
async function verifyToken(req, res, next) {
    const authHeader = req.headers.authorization || "";
    if (!authHeader.startsWith("Bearer ")) return res.status(401).json({ error: "No token provided" });
    try {
        const decoded = await admin.auth().verifyIdToken(authHeader.split(" ")[1]);
        req.decoded = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ error: "Invalid or expired token" });
    }
}

// ---------- Role Verification Middleware ----------
async function verifyAdmin(req, res, next) {
    const { db } = await connectDB();
    const user = await db.collection("users").findOne({ email: req.decoded.email.toLowerCase() });
    if (!user || user.role !== "admin") return res.status(403).json({ error: "Admin access only" });
    next();
}

async function verifyUser(req, res, next) {
    const { db } = await connectDB();
    const user = await db.collection("users").findOne({ email: req.decoded.email.toLowerCase() });
    if (!user) return res.status(404).json({ error: "User not found" });
    next();
}

// ---------- Routes ----------

// Health Check
app.get("/", (req, res) => res.json({ status: "ok", message: "Forum API Running" }));

// --- Users ---
app.post("/users", async (req, res) => {
    const { db } = await connectDB();
    const usersCollection = db.collection("users");
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
});

app.get("/users", async (req, res) => {
    const { db } = await connectDB();
    const { email } = req.query;

    if (email) {
        const user = await db.collection("users").findOne({ email: email.toLowerCase() });
        return user ? res.json({ success: true, data: [user] }) : res.status(404).json({ error: "User not found" });
    }

    const users = await db.collection("users").find().toArray();
    res.json({ success: true, data: users });
});

app.get("/users/role/:email", verifyToken, async (req, res) => {
    const { db } = await connectDB();
    const user = await db.collection("users").findOne({ email: req.params.email.toLowerCase() });
    user ? res.json({ success: true, role: user.role, user_status: user.user_status || "Bronze", membership: user.membership || "no" })
        : res.status(404).json({ error: "User not found" });
});

app.get("/users/profile", verifyToken, verifyUser, async (req, res) => {
    const { db } = await connectDB();
    const email = req.query.email?.toLowerCase();
    if (!email) return res.status(400).json({ error: "Email required" });

    const user = await db.collection("users").findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });

    const posts = await db.collection("posts").find({ authorEmail: email }).sort({ creation_time: -1 }).limit(3).toArray();
    const totalPosts = await db.collection("posts").countDocuments({ authorEmail: email });

    res.json({ ...user, recentPosts: posts, totalPostCount: totalPosts });
});

app.get("/users/home-stats", verifyToken, verifyUser, async (req, res) => {
    const { db } = await connectDB();
    const email = req.query.email?.toLowerCase();
    if (!email) return res.status(400).json({ error: "Email required" });

    const result = await db.collection("posts").aggregate([
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
    const { db } = await connectDB();
    const { aboutMe } = req.body;
    const result = await db.collection("users").findOneAndUpdate(
        { email: req.decoded.email.toLowerCase() },
        { $set: { aboutMe } },
        { returnDocument: "after" }
    );
    result ? res.json({ aboutMe: result.aboutMe }) : res.status(404).json({ error: "User not found" });
});

app.patch("/users/make-admin/:id", verifyToken, verifyAdmin, async (req, res) => {
    const { db } = await connectDB();
    if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: "Invalid ID" });

    const result = await db.collection("users").updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: { role: "admin" } }
    );
    result.modifiedCount === 0 ? res.status(404).json({ error: "User not found" }) : res.json({ success: true });
});

// --- Tags ---
app.get("/tags", async (req, res) => {
    const { db } = await connectDB();
    const tags = await db.collection("tags").find().toArray();
    res.json(tags);
});

app.post("/addtags", verifyToken, async (req, res) => {
    const { db } = await connectDB();
    const { tag } = req.body;
    if (!tag) return res.status(400).json({ error: "Tag required" });

    const existing = await db.collection("tags").findOne({ name: tag });
    if (existing) return res.status(400).json({ error: "Tag already exists" });

    const result = await db.collection("tags").insertOne({ name: tag });
    res.json({ success: true, insertedId: result.insertedId });
});

// --- Posts ---
app.post("/posts", verifyToken, verifyUser, async (req, res) => {
    const { db } = await connectDB();
    const post = { ...req.body, authorEmail: req.body.authorEmail.toLowerCase(), createdAt: new Date() };
    const result = await db.collection("posts").insertOne(post);

    if (result.insertedId) {
        await db.collection("users").updateOne({ email: post.authorEmail }, { $inc: { posts: 1 } });
    }

    res.status(201).json({ success: true, insertedId: result.insertedId });
});

app.get("/posts", async (req, res) => {
    const { db } = await connectDB();
    const { sort, page = 1, limit = 5 } = req.query;
    const pageNumber = parseInt(page);
    const pageSize = parseInt(limit);

    let cursor = db.collection("posts").find();
    cursor = sort === "popularity" ? cursor.sort({ vote: -1 }) : cursor.sort({ creation_time: -1 });

    const totalPosts = await db.collection("posts").countDocuments();
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
    const { db } = await connectDB();
    if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: "Invalid ID" });

    const post = await db.collection("posts").findOne({ _id: new ObjectId(req.params.id) });
    post ? res.json(post) : res.status(404).json({ error: "Post not found" });
});

app.get("/myposts/:email", verifyToken, verifyUser, async (req, res) => {
    const { db } = await connectDB();
    const { email } = req.params;

    if (email.toLowerCase() !== req.decoded.email.toLowerCase()) {
        return res.status(403).json({ error: "Access denied" });
    }

    const posts = await db.collection("posts").find({ authorEmail: email.toLowerCase() }).sort({ creation_time: -1 }).toArray();
    res.json({ success: true, data: posts, count: posts.length });
});

app.post("/posts/search", async (req, res) => {
    const { db } = await connectDB();
    const { tag } = req.body;
    if (!tag?.trim()) return res.json({ posts: [] });

    const posts = await db.collection("posts").find({ tag: { $regex: tag.trim(), $options: "i" } }).toArray();
    res.json({ posts });
});

app.delete("/posts/:id", verifyToken, async (req, res) => {
    const { db } = await connectDB();
    if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: "Invalid ID" });

    const result = await db.collection("posts").deleteOne({ _id: new ObjectId(req.params.id) });
    result.deletedCount === 0 ? res.status(404).json({ error: "Post not found" }) : res.json({ success: true });
});

app.post("/posts/:postId/vote", verifyToken, async (req, res) => {
    const { db } = await connectDB();
    const { postId } = req.params;
    const { type } = req.body;
    const userEmail = req.decoded.email.toLowerCase();

    if (!['upvote', 'downvote'].includes(type)) return res.status(400).json({ error: "Invalid vote type" });

    const post = await db.collection("posts").findOne({ _id: new ObjectId(postId) });
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
    const result = await db.collection("posts").findOneAndUpdate(
        { _id: new ObjectId(postId) },
        { $set: { upVote, downVote, vote, upvote_by, downvote_by } },
        { returnDocument: "after" }
    );

    result ? res.json({ upVote, downVote, vote, upvote_by, downvote_by }) : res.status(404).json({ error: "Update failed" });
});

// --- Comments ---
app.post("/posts/:id/comment", verifyToken, async (req, res) => {
    const { db } = await connectDB();
    const { id } = req.params;
    const { comment } = req.body;
    const userEmail = req.decoded.email.toLowerCase();

    const userData = await db.collection("users").findOne({ email: userEmail });
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

    await db.collection("comments").insertOne(newComment);
    await db.collection("posts").updateOne({ _id: new ObjectId(id) }, { $push: { comments: newComment } });

    res.status(201).json(newComment);
});

app.get("/posts/:id/comments", verifyToken, async (req, res) => {
    const { db } = await connectDB();
    const { id } = req.params;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;

    const totalComments = await db.collection("comments").countDocuments({ postId: id });
    const comments = await db.collection("comments").find({ postId: id }).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray();

    res.json({ comments, totalComments });
});

app.get("/comments/:id", verifyToken, async (req, res) => {
    const { db } = await connectDB();
    if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: "Invalid ID" });

    const comment = await db.collection("comments").findOne({ _id: new ObjectId(req.params.id) });
    comment ? res.json({ success: true, data: comment }) : res.status(404).json({ error: "Comment not found" });
});

app.delete("/comments/:id", verifyToken, verifyAdmin, async (req, res) => {
    const { db } = await connectDB();
    if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: "Invalid ID" });

    const comment = await db.collection("comments").findOne({ _id: new ObjectId(req.params.id) });
    if (!comment) return res.status(404).json({ error: "Comment not found" });

    await db.collection("comments").deleteOne({ _id: new ObjectId(req.params.id) });
    await db.collection("posts").updateOne({ _id: new ObjectId(comment.postId) }, { $pull: { comments: { _id: new ObjectId(req.params.id) } } });

    res.json({ success: true });
});

// --- Reports ---
app.post("/comments/:commentId/report", verifyToken, verifyUser, async (req, res) => {
    const { db } = await connectDB();
    const { commentId } = req.params;
    const { feedback, postId } = req.body;
    const reporterEmail = req.decoded.email.toLowerCase();

    if (!feedback || !postId) return res.status(400).json({ error: "Feedback and postId required" });

    const existing = await db.collection("reports").findOne({ commentId, reporterEmail });
    if (existing) return res.status(400).json({ error: "Already reported" });

    const newReport = { commentId, postId, reporterEmail, feedback, reportedAt: new Date(), status: "pending" };
    const result = await db.collection("reports").insertOne(newReport);

    await db.collection("posts").updateOne(
        { _id: new ObjectId(postId), "comments._id": new ObjectId(commentId) },
        { $inc: { "comments.$.reportCount": 1 }, $addToSet: { "comments.$.reportedBy": reporterEmail } }
    );

    res.json({ success: true, insertedId: result.insertedId });
});

app.get("/comments/:commentId/report-status", verifyToken, async (req, res) => {
    const { db } = await connectDB();
    const report = await db.collection("reports").findOne({ commentId: req.params.commentId, reporterEmail: req.decoded.email.toLowerCase() });
    res.json({ success: true, hasReported: !!report, reportedAt: report?.reportedAt || null });
});

app.get("/reports", verifyToken, verifyUser, async (req, res) => {
    const { db } = await connectDB();
    const { page = 1, limit = 10 } = req.query;
    const pageNumber = parseInt(page);
    const pageSize = parseInt(limit);

    const query = { reporterEmail: req.decoded.email.toLowerCase() };
    const totalReports = await db.collection("reports").countDocuments(query);
    const reports = await db.collection("reports").find(query).sort({ reportedAt: -1 }).skip((pageNumber - 1) * pageSize).limit(pageSize).toArray();

    res.json({ success: true, data: reports, totalReports, totalPages: Math.ceil(totalReports / pageSize), currentPage: pageNumber });
});

app.get("/reportsforadmin", verifyToken, verifyAdmin, async (req, res) => {
    const { db } = await connectDB();
    const { page = 1, limit = 10, status = "pending" } = req.query;
    const pageNumber = parseInt(page);
    const pageSize = parseInt(limit);

    const query = { status };
    const totalReports = await db.collection("reports").countDocuments(query);
    const reports = await db.collection("reports").find(query).sort({ reportedAt: -1 }).skip((pageNumber - 1) * pageSize).limit(pageSize).toArray();

    res.json({ success: true, data: reports, totalReports, totalPages: Math.ceil(totalReports / pageSize), currentPage: pageNumber });
});

app.put("/reports/:reportId/status", verifyToken, verifyAdmin, async (req, res) => {
    const { db } = await connectDB();
    const { status } = req.body;

    if (!["pending", "reviewed", "resolved"].includes(status)) {
        return res.status(400).json({ error: "Invalid status" });
    }

    const result = await db.collection("reports").updateOne(
        { _id: new ObjectId(req.params.reportId) },
        { $set: { status, updatedAt: new Date(), updatedBy: req.decoded.email.toLowerCase() } }
    );

    result.matchedCount === 0 ? res.status(404).json({ error: "Report not found" }) : res.json({ success: true });
});

app.delete("/reports/:id", verifyToken, verifyAdmin, async (req, res) => {
    const { db } = await connectDB();
    if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: "Invalid ID" });

    const result = await db.collection("reports").deleteOne({ _id: new ObjectId(req.params.id) });
    result.deletedCount === 0 ? res.status(404).json({ error: "Report not found" }) : res.json({ success: true });
});

// --- Announcements ---
app.post("/announcements", verifyToken, verifyAdmin, async (req, res) => {
    const { db } = await connectDB();
    const { authorName, authorEmail, authorImage, title, description } = req.body;

    if (!authorName || !authorEmail || !title || !description) {
        return res.status(400).json({ error: "Missing required fields" });
    }

    const announcement = { authorName, authorEmail, authorImage, title, description, creation_time: new Date() };
    const result = await db.collection("announcements").insertOne(announcement);
    res.status(201).json({ success: true, insertedId: result.insertedId });
});

app.get("/announcements", async (req, res) => {
    const { db } = await connectDB();
    const announcements = await db.collection("announcements").find().sort({ creation_time: -1 }).toArray();
    res.json(announcements);
});

app.get("/announcements/count", async (req, res) => {
    const { db } = await connectDB();
    const count = await db.collection("announcements").countDocuments();
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
    const { db } = await connectDB();
    const { email, amount, transactionId, cardType, cardOwner } = req.body;

    if (!email || !transactionId) return res.status(400).json({ error: "Invalid payment data" });

    const payment = { email: email.toLowerCase(), amount, transactionId, cardType, cardOwner, status: "succeeded", createdAt: new Date() };
    await db.collection("payments").insertOne(payment);

    await db.collection("users").updateOne(
        { email: email.toLowerCase() },
        { $set: { membership: "yes", user_status: "Gold" } }
    );

    res.json({ success: true });
});

// --- Stats ---
app.get("/api/posts/count", async (req, res) => {
    const { db } = await connectDB();
    const count = await db.collection("posts").countDocuments();
    res.json({ count });
});

app.get("/api/comments/count", async (req, res) => {
    const { db } = await connectDB();
    const count = await db.collection("comments").countDocuments();
    res.json({ count });
});

app.get("/api/users/count", async (req, res) => {
    const { db } = await connectDB();
    const count = await db.collection("users").countDocuments();
    res.json({ count });
});

// --- 404 ---
app.use("*", (_, res) => res.status(404).json({ error: "Route not found" }));

// ✅ Export for Vercel
export default app;