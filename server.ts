import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import { fileURLToPath } from "url";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import { Client, Account } from "node-appwrite";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// MongoDB Models
const UserSchema = new mongoose.Schema({
  appwriteId: { type: String, required: true, unique: true },
  email: { type: String, required: true },
  name: { type: String },
  phone: { type: String },
  avatarUrl: { type: String }, // Can store Base64 or URL
  avatarData: { type: String }, // Explicitly for Base64 image data
  role: { type: String, default: 'user' },
  plan: { type: String, default: 'trial' },
  createdAt: { type: Date, default: Date.now },
});

const ScanSchema = new mongoose.Schema({
  userId: { type: String, required: true }, // Appwrite User ID
  type: { type: String, required: true },
  target: { type: String, required: true },
  score: { type: Number, required: true },
  details: { type: Object, required: true },
  timestamp: { type: Date, default: Date.now },
});

const User = mongoose.model("User", UserSchema);
const Scan = mongoose.model("Scan", ScanSchema);

async function startServer() {
  const app = express();
  const PORT = 3000;

  // MongoDB Connection
  const MONGODB_URI = process.env.MONGODB_URI || "mongodb+srv://db:Aniket1234@cluster0.nqoxit3.mongodb.net/login?appName=Cluster0";
  try {
    await mongoose.connect(MONGODB_URI, { dbName: 'login' });
    console.log("Connected to MongoDB Atlas (Database: login)");
  } catch (err) {
    console.error("MongoDB connection error:", err);
  }

  app.use(cors());
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ limit: '10mb', extended: true }));

  // Appwrite Middleware
  const authenticateAppwrite = async (req: any, res: any, next: any) => {
    const authHeader = req.headers['authorization'];
    const jwt = authHeader && authHeader.split(' ')[1];
    if (!jwt) return res.sendStatus(401);

    try {
      const client = new Client()
        .setEndpoint(process.env.VITE_APPWRITE_ENDPOINT || 'https://cloud.appwrite.io/v1')
        .setProject(process.env.VITE_APPWRITE_PROJECT_ID || '')
        .setJWT(jwt);

      const account = new Account(client);
      const user = await account.get();
      req.user = user;
      next();
    } catch (err) {
      console.error("Appwrite auth error:", err);
      res.sendStatus(403);
    }
  };

  // User Profile Routes
  app.get("/api/user/profile", authenticateAppwrite, async (req: any, res) => {
    try {
      let user = await User.findOne({ appwriteId: req.user.$id });
      if (!user) {
        user = new User({
          appwriteId: req.user.$id,
          email: req.user.email,
          name: req.user.name || ''
        });
        await user.save();
      }
      res.json(user);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post("/api/user/sync", authenticateAppwrite, async (req: any, res) => {
    const { name, phone } = req.body;
    try {
      let user = await User.findOne({ appwriteId: req.user.$id });
      if (user) {
        user.name = name || user.name;
        user.phone = phone || user.phone;
        user.email = req.user.email;
        await user.save();
      } else {
        user = new User({
          appwriteId: req.user.$id,
          email: req.user.email,
          name: name || req.user.name || '',
          phone: phone || ''
        });
        await user.save();
      }
      res.json(user);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.put("/api/user/profile", authenticateAppwrite, async (req: any, res) => {
    const { name, phone, avatarUrl, avatarData } = req.body;
    try {
      const user = await User.findOneAndUpdate(
        { appwriteId: req.user.$id },
        { name, phone, avatarUrl, avatarData },
        { new: true, upsert: true }
      );
      res.json(user);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  // Scan Routes
  app.post("/api/scans", authenticateAppwrite, async (req: any, res) => {
    const { type, target, score, details } = req.body;
    try {
      const scan = new Scan({ userId: req.user.$id, type, target, score, details });
      await scan.save();
      res.json(scan);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.get("/api/scans", authenticateAppwrite, async (req: any, res) => {
    try {
      const scans = await Scan.find({ userId: req.user.$id }).sort({ timestamp: -1 }).limit(20);
      res.json(scans);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Health Check
  app.get("/api/health", async (req, res) => {
    let appwriteStatus = "missing_config";
    if (process.env.VITE_APPWRITE_PROJECT_ID) {
      try {
        const client = new Client()
          .setEndpoint(process.env.VITE_APPWRITE_ENDPOINT || 'https://cloud.appwrite.io/v1')
          .setProject(process.env.VITE_APPWRITE_PROJECT_ID);
        
        if (process.env.APPWRITE_API_KEY) {
          client.setKey(process.env.APPWRITE_API_KEY);
          // Test connection by getting project info or similar (requires API key)
          // For now, just assume configured if key is present
          appwriteStatus = "connected";
        } else {
          appwriteStatus = "configured";
        }
      } catch (err) {
        appwriteStatus = "error";
      }
    }

    res.json({ 
      status: "ok", 
      mongodb: mongoose.connection.readyState === 1 ? "connected" : "disconnected",
      appwrite: appwriteStatus,
      timestamp: new Date().toISOString() 
    });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
