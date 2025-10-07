app.get("/", (req, res) => {
  res.send("✅ Barter Trade backend is running successfully!");
});

// ------------------
// server.js - Backend with REST + Socket.IO, Search/Filter, Pagination, Image Upload
// ------------------

require("dotenv").config();

const express = require("express");
const http = require("http");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Server } = require("socket.io");
const multer = require("multer");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "secretkey";

// HTTP server for Socket.IO
const server = http.createServer(app);

// Initialize Socket.IO
const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"] }
});

app.use(express.json());

// Serve uploaded images
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ------------------
// MongoDB Connection
// ------------------
const mongoURI = process.env.MONGO_URI;
if (!mongoURI) { console.error("❌ MongoDB connection string is missing in .env!"); process.exit(1); }

mongoose.connect(mongoURI)
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// ------------------
// Schemas & Models
// ------------------
const userSchema = new mongoose.Schema({ name: String, email: { type: String, unique: true }, password: String, phone: String });
const User = mongoose.model("User", userSchema);

const itemSchema = new mongoose.Schema({
  name: String,
  description: String,
  price: Number,
  category: String,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  imageUrl: String
});
const Item = mongoose.model("Item", itemSchema);

const tradeSchema = new mongoose.Schema({
  fromUser: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  toUser: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  itemOffered: { type: mongoose.Schema.Types.ObjectId, ref: "Item" },
  itemRequested: { type: mongoose.Schema.Types.ObjectId, ref: "Item" },
  status: { type: String, enum: ["pending", "accepted", "rejected"], default: "pending" },
  createdAt: { type: Date, default: Date.now }
});
const Trade = mongoose.model("Trade", tradeSchema);

const messageSchema = new mongoose.Schema({
  fromUser: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  toUser: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  tradeId: { type: mongoose.Schema.Types.ObjectId, ref: "Trade" },
  content: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});
const Message = mongoose.model("Message", messageSchema);

// ------------------
// JWT Auth Middleware
// ------------------
const auth = (req, res, next) => {
  const token = (req.header("Authorization") || "").replace("Bearer ", "");
  if (!token) return res.status(401).json({ success: false, message: "No token provided" });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); } catch (err) { return res.status(401).json({ success: false, message: "Invalid token" }); }
};

// ------------------
// Socket.IO User Tracking
// ------------------
const onlineUsers = new Map();
function addSocketForUser(userId, socketId) { const s = onlineUsers.get(userId) || new Set(); s.add(socketId); onlineUsers.set(userId, s); }
function removeSocketForUser(userId, socketId) { const s = onlineUsers.get(userId); if (!s) return; s.delete(socketId); if (!s.size) onlineUsers.delete(userId); else onlineUsers.set(userId, s); }
function getSocketIdsForUser(userId) { const s = onlineUsers.get(userId); return s ? Array.from(s) : []; }

// ------------------
// Socket.IO Auth & Events
// ------------------
io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token || socket.handshake.query?.token;
    if (!token) return next(new Error("Authentication error: token required"));
    socket.user = jwt.verify(token.replace("Bearer ", ""), JWT_SECRET);
    next();
  } catch (err) { next(new Error("Authentication error: invalid token")); }
});
io.on("connection", (socket) => {
  const userId = socket.user.id;
  addSocketForUser(userId, socket.id);
  socket.emit("connected", { message: "Connected", userId });
  socket.on("disconnect", () => removeSocketForUser(userId, socket.id));
});

// ------------------
// Multer Setup for Image Upload
// ------------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png/;
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, allowed.test(ext) ? true : new Error('Only images are allowed'));
  }
});

// ------------------
// AUTH Routes (Register/Login)
// ------------------
app.post("/register", async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    if (!name || !email || !password) return res.status(400).json({ success: false, message: "All fields required" });
    if (await User.findOne({ email })) return res.status(400).json({ success: false, message: "Email exists" });
    const hashed = await bcrypt.hash(password, 10);
    const newUser = await User.create({ name, email, password: hashed, phone });
    res.json({ success: true, user: { id: newUser._id, name, email, phone } });
  } catch (err) { res.status(500).json({ success: false, message: "Server error" }); }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ success: false, message: "Invalid credentials" });
    if (!await bcrypt.compare(password, user.password)) return res.status(400).json({ success: false, message: "Invalid credentials" });
    const token = jwt.sign({ id: user._id, email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token });
  } catch (err) { res.status(500).json({ success: false, message: "Server error" }); }
});

// ------------------
// Profile Routes
// ------------------
app.get("/profile", auth, async (req, res) => {
  const user = await User.findById(req.user.id).select("-password");
  res.json({ success: true, user });
});
app.put("/profile", auth, async (req, res) => {
  const { name, phone } = req.body;
  const user = await User.findByIdAndUpdate(req.user.id, { name, phone }, { new: true }).select("-password");
  res.json({ success: true, user });
});

// ------------------
// Items Routes with Search/Filter/Pagination + Image Upload
// ------------------
app.post("/api/items", auth, upload.single('image'), async (req, res) => {
  try {
    const { name, description, price, category } = req.body;
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : undefined;
    const item = await Item.create({ name, description, price, category, userId: req.user.id, imageUrl });
    res.status(201).json({ success: true, item });
  } catch (err) { res.status(500).json({ success: false, message: "Server error" }); }
});

app.get("/api/items", async (req, res) => {
  try {
    let { page = 1, limit = 10, name, category, minPrice, maxPrice, sort } = req.query;
    page = parseInt(page); limit = parseInt(limit);
    const filter = {};
    if (name) filter.name = { $regex: name, $options: 'i' };
    if (category) filter.category = category;
    if (minPrice) filter.price = { ...filter.price, $gte: parseFloat(minPrice) };
    if (maxPrice) filter.price = { ...filter.price, $lte: parseFloat(maxPrice) };
    let query = Item.find(filter).populate("userId", "name email");
    if (sort) {
      const [field, order] = sort.split('_');
      query = query.sort({ [field]: order === 'desc' ? -1 : 1 });
    }
    const totalItems = await Item.countDocuments(filter);
    const totalPages = Math.ceil(totalItems / limit);
    const items = await query.skip((page - 1) * limit).limit(limit);
    res.json({ success: true, items, totalItems, totalPages, currentPage: page });
  } catch (err) { res.status(500).json({ success: false, message: "Server error" }); }
});

app.get("/api/items/:id", async (req, res) => {
  const item = await Item.findById(req.params.id).populate("userId", "name email");
  if (!item) return res.status(404).json({ success: false, message: "Item not found" });
  res.json({ success: true, item });
});

// ------------------
// Trades Routes with Pagination & Filtering
// ------------------
app.get("/trades", auth, async (req, res) => {
  try {
    let { page = 1, limit = 10, status } = req.query;
    page = parseInt(page); limit = parseInt(limit);
    const filter = { $or: [{ fromUser: req.user.id }, { toUser: req.user.id }] };
    if (status) filter.status = status;
    const totalItems = await Trade.countDocuments(filter);
    const totalPages = Math.ceil(totalItems / limit);
    const trades = await Trade.find(filter)
      .populate("itemOffered")
      .populate("itemRequested")
      .populate("fromUser", "name email")
      .populate("toUser", "name email")
      .skip((page - 1) * limit).limit(limit);
    res.json({ success: true, trades, totalItems, totalPages, currentPage: page });
  } catch (err) { res.status(500).json({ success: false, message: "Server error" }); }
});

// ------------------
// Start Server
// ------------------
server.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
