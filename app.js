

import express from "express";
import { createServer } from "http";
import mongoose from "mongoose";
import session from "express-session";
import passport from "passport";
import ejsmate from "ejs-mate";
import crypto from "crypto";
import Razorpay from "razorpay";
import https from "https";
import { configDotenv } from "dotenv";
import Notification from "./model/Notification.js";
import User from "./model/user.js";
import UserProfile from "./model/user.profile.js";
import { isLoggedIn } from "./middleware/auth.js";
import { isAdmin } from "./middleware/isAdmin.js";

import Chat from "./model/chat.js";
import { Server } from "socket.io";
import { v2 as cloudinary } from "cloudinary";
import multer from "multer";
import { CloudinaryStorage } from "multer-storage-cloudinary";
import Blog from "./model/Blog.js";
import MongoStore from "connect-mongo";
import rateLimit from "express-rate-limit";



configDotenv();
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});
const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: "shaadiwali_profiles",
    allowed_formats: ["jpg", "jpeg", "png", "webp"]
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize:  5 * 1024 * 1024 
  }
});






const app = express();
const server = createServer(app);
const PORT = process.env.PORT || 3000;
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});
// ================= CHAT PRESENCE STORAGE =================
const chatRoomUsers = new Map(); 
// roomId -> Set of phones currently inside chat page

const PLAN_ALIASES = {
  Standard: "standard",
  standard: "standard",
  Basic: "Basic",
  Premium: "Premium",
  Elite: "Elite",
  "Elite-3": "Elite-3",
  "Elite-6": "Elite-6",
  NRI: "NRI",
  "NRI-3": "NRI-3",
  "NRI-6": "NRI-6"
};

const normalizeSubscriptionPlan = (plan) => {
  if (!plan || plan === "None") return null;
  return PLAN_ALIASES[plan] || plan;
};

const CHAT_ENABLED_PLANS = new Set([
  "Basic",
  "standard",
  "Premium",
  "Elite",
  "Elite-3",
  "Elite-6",
  "NRI",
  "NRI-3",
  "NRI-6"
]);

const VOICE_CALL_ENABLED_PLANS = new Set([
  "standard",
  "Premium",
  "Elite",
  "Elite-3",
  "Elite-6",
  "NRI",
  "NRI-3",
  "NRI-6"
]);

const VIDEO_CALL_ENABLED_PLANS = new Set([
  "Premium",
  "Elite",
  "Elite-3",
  "Elite-6",
  "NRI",
  "NRI-3",
  "NRI-6"
]);

const hasPlanAccess = (profile, allowedPlans) => {
  const normalizedPlan = normalizeSubscriptionPlan(profile?.subscriptionPlan);
  return Boolean(profile?.isSubscribed && normalizedPlan && allowedPlans.has(normalizedPlan));
};

const SITE_URL = (process.env.SITE_URL || "https://shaadiwali.com").replace(/\/$/, "");
const DEFAULT_OG_IMAGE = `${SITE_URL}/images/Logo1.jpeg`;

const SEO_PAGES = {
  "/": {
    title: "Indian Matrimonial & Matchmaking Services | Shaadiwali",
    description: "Find verified matrimonial profiles, trusted matchmaking services, and meaningful connections across India. Start your journey with Shaadiwali today."
  },
  "/pricing": {
    title: "Pricing Plans - Verified Matchmaking Services | Shaadiwali",
    description: "Explore affordable matchmaking plans with verified profiles, priority support, and personalized matrimonial services from Shaadiwali."
  },
  "/about-us": {
    title: "About Shaadiwali - Trusted Indian Matrimonial Platform",
    description: "Learn how Shaadiwali helps individuals and families find compatible life partners through trusted, secure, and verified matchmaking services."
  },
  "/contact-us": {
    title: "Contact Shaadiwali - Matrimonial Support & Assistance",
    description: "Contact Shaadiwali for matrimonial support, profile assistance, membership inquiries, and expert guidance throughout your matchmaking journey."
  },
  "/customer-support": {
    title: "Customer Support - Get Help with Your Matrimonial Journey",
    description: "Get quick assistance for profile management, account issues, membership plans, and matrimonial services through Shaadiwali support."
  },
  "/privacy-policy": {
    title: "Privacy Policy | Shaadiwali Matrimonial Services",
    description: "Read Shaadiwali's privacy policy to understand how we collect, protect, and manage your personal information and matrimonial data."
  },
  "/terms-of-use": {
    title: "Terms of Use | Shaadiwali",
    description: "Review the terms and conditions governing the use of Shaadiwali's matrimonial platform, services, memberships, and user accounts."
  },
  "/be-safe-online": {
    title: "Online Matrimonial Safety Tips & Guidelines | Shaadiwali",
    description: "Stay safe while searching for a life partner with expert online matrimonial safety tips, scam prevention advice, and privacy guidelines."
  },
  "/login": {
    title: "Member Login | Shaadiwali Matrimonial Platform",
    description: "Securely log in to your Shaadiwali account to manage your matrimonial profile, connect with matches, and access premium features.",
    robots: "noindex,follow"
  },
  "/blogs": {
    title: "Matrimonial Advice, Relationship Tips & Marriage Blogs | Shaadiwali",
    description: "Read expert relationship advice, marriage tips, matchmaking insights, and matrimonial success stories on the Shaadiwali blog."
  },
  "/profile/edit": {
    title: "Edit Your Matrimonial Profile | Shaadiwali",
    description: "Update your matrimonial profile, preferences, photos, and personal details to improve visibility and attract compatible matches.",
    robots: "noindex,follow"
  }
};

const buildOrganizationSchema = () => ({
  "@context": "https://schema.org",
  "@type": "Organization",
  name: "Shaadiwali",
  url: SITE_URL,
  logo: DEFAULT_OG_IMAGE,
  sameAs: [
    "https://www.youtube.com/@Shaadiwalidotcom"
  ]
});

const buildWebsiteSchema = () => ({
  "@context": "https://schema.org",
  "@type": "WebSite",
  name: "Shaadiwali",
  url: SITE_URL,
  potentialAction: {
    "@type": "SearchAction",
    target: `${SITE_URL}/people?name={search_term_string}`,
    "query-input": "required name=search_term_string"
  }
});

const buildFaqSchema = () => ({
  "@context": "https://schema.org",
  "@type": "FAQPage",
  mainEntity: [
    {
      "@type": "Question",
      name: "How does Shaadiwali verify matrimonial profiles?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "Shaadiwali supports profile verification so members can connect with more confidence while searching for compatible life partners."
      }
    },
    {
      "@type": "Question",
      name: "Can I browse matrimonial profiles before choosing a plan?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "Members can browse profiles and choose a matchmaking plan when they need expanded access, priority support, and premium features."
      }
    },
    {
      "@type": "Question",
      name: "How can I stay safe while using Shaadiwali?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "Keep conversations inside the platform, avoid sharing sensitive personal details early, and report suspicious activity to Shaadiwali support."
      }
    }
  ]
});

const buildPersonSchema = (person, canonicalUrl) => ({
  "@context": "https://schema.org",
  "@type": "Person",
  name: `${person.first_name || ""} ${person.last_name || ""}`.trim() || "Shaadiwali Member",
  url: canonicalUrl,
  image: person.image || DEFAULT_OG_IMAGE,
  address: person.address || undefined,
  gender: person.gender || undefined
});

const escapeXml = (value = "") => String(value)
  .replace(/&/g, "&amp;")
  .replace(/</g, "&lt;")
  .replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;")
  .replace(/'/g, "&apos;");

const buildSeo = (req, overrides = {}) => {
  const path = req.path === "" ? "/" : req.path;
  const base = SEO_PAGES[path] || {};
  const canonicalPath = overrides.canonicalPath || path;
  const canonicalUrl = overrides.canonicalUrl || `${SITE_URL}${canonicalPath === "/" ? "/" : canonicalPath}`;
  const title = overrides.title || base.title || "Shaadiwali";
  const description = overrides.description || base.description || "Find verified matrimonial profiles and trusted matchmaking services on Shaadiwali.";

  return {
    title,
    description,
    canonicalUrl,
    robots: overrides.robots || base.robots || "index,follow",
    ogTitle: overrides.ogTitle || title,
    ogDescription: overrides.ogDescription || description,
    ogUrl: overrides.ogUrl || canonicalUrl,
    ogImage: overrides.ogImage || DEFAULT_OG_IMAGE,
    ogType: overrides.ogType || "website",
    schema: overrides.schema || (path === "/" ? [buildOrganizationSchema(), buildWebsiteSchema(), buildFaqSchema()] : [])
  };
};

/* ===================== DB ===================== */
mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.error(err));

/* ===================== CHAT SESSION AUTO CLEAN ===================== */




/* ===================== APP CONFIG ===================== */
app.engine("ejs", ejsmate);
app.set("trust proxy", 1);
app.set("view engine", "ejs");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  express.static("public", {
    maxAge: "30d", // cache static files for 30 days
    etag: true,
  })
);

/* ===================== SESSION ===================== */
app.use(
  session({
    name: "shaadi.sid",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false, // ❗ change this
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URL,
      ttl: 14 * 24 * 60 * 60
    }),
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 7
    }
  })
);

/* ===================== PASSPORT ===================== */
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});

/* ===================== GLOBAL LOCALS ===================== */
app.use(async (req, res, next) => {
    res.locals.user = req.user || null;
  
    if (req.user?.phone) {
      res.locals.userProfile = await UserProfile.findOne({
        phone: req.user.phone
      });
    } else {
      res.locals.userProfile = null;
    }
    res.locals.isAdmin = req.user?.isAdmin === true;
  
    next();
  });
app.use((req, res, next) => {
  res.locals.siteUrl = SITE_URL;
  res.locals.gtmId = process.env.GTM_ID || process.env.GOOGLE_TAG_MANAGER_ID || "";
  res.locals.currentPath = req.path;
  res.locals.seo = buildSeo(req);
  next();
});
  //subscription cancle 
  app.use(async (req, res, next) => {
    if (req.user?.phone) {
      const profile = await UserProfile.findOne({ phone: req.user.phone });
  
      if (
        profile?.isSubscribed &&
        profile.subscriptionExpiresAt &&
        profile.subscriptionExpiresAt < new Date()
      ) {
        profile.isSubscribed = false;
        profile.subscriptionPlan = null;
        profile.subscriptionExpiresAt = null;
        await profile.save();
      }
  
      res.locals.userProfile = profile;
    }
    next();
  });
  



  io.on("connection", (socket) => {
    socket.on("join_call", ({ roomId }) => {
      socket.join(roomId);
    });
  
    socket.on("offer", ({ roomId, offer }) => {
      socket.to(roomId).emit("offer", offer);
    });
  
    socket.on("answer", ({ roomId, answer }) => {
      socket.to(roomId).emit("answer", answer);
    });
  
    socket.on("ice_candidate", ({ roomId, candidate }) => {
      socket.to(roomId).emit("ice_candidate", candidate);
    });
  
    socket.on("end_call", ({ roomId }) => {
      socket.to(roomId).emit("end_call");
    });
    // Now joining by phone instead of ID
    socket.on("join user room", (phone) => {
      if (phone) {
        socket.join(phone.toString());
        
      }
    });
    socket.on("call_time_ended", ({ roomId }) => {
      // Send popup only to specific user
      socket.to(roomId).emit("show_extend_popup");
    });
    // ================= CHAT ROOM PRESENCE =================

socket.on("join_chat_room", ({ roomId, phone }) => {
  if (!roomId || !phone) return;

  socket.join(roomId);

  socket.data.roomId = roomId;
  socket.data.phone = phone;

  if (!chatRoomUsers.has(roomId)) {
    chatRoomUsers.set(roomId, new Set());
  }

  chatRoomUsers.get(roomId).add(phone.toString());

  const users = [...chatRoomUsers.get(roomId)];

  io.to(roomId).emit("chat_presence", {
    users,
    count: users.length
  });
});

socket.on("disconnect", () => {
  const roomId = socket.data.roomId;
  const phone = socket.data.phone;

  if (roomId && phone && chatRoomUsers.has(roomId)) {
    chatRoomUsers.get(roomId).delete(phone.toString());

    if (chatRoomUsers.get(roomId).size === 0) {
      chatRoomUsers.delete(roomId);
    }

    const users = chatRoomUsers.has(roomId)
      ? [...chatRoomUsers.get(roomId)]
      : [];

    io.to(roomId).emit("chat_presence", {
      users,
      count: users.length
    });
  }
});
      // 📞 Incoming Call Notification
      socket.on("incoming_call", async ({ to, from, callerName, callUrl, type }) => {

        if (!to) return;
      
        console.log(`📞 Incoming call from ${from} to ${to}`);
      
        // send realtime call popup
        io.to(to.toString()).emit("incoming_call", {
          from,
          callerName,
          callUrl
        });
      
        // check if receiver online
        const sockets = await io.in(to.toString()).fetchSockets();
      
        
      
          try {
      
            await sendCallSMS(
              to,
              callerName || "Someone",
              callUrl,
              type || "video"
            );
      
            console.log("📩 Call SMS sent");
      
          } catch (err) {
            console.error("SMS sending failed:", err);
          }
      
        
      
      });
    });

      
  




  function sendNewMessageSMS(phone, senderName) {
    return new Promise((resolve, reject) => {
  
      const options = {
        method: "POST",
        hostname: "control.msg91.com",
        path: "/api/v5/flow/",
        headers: {
          "authkey": process.env.MSG91_AUTH_KEY,
          "Content-Type": "application/json"
        }
      };
  
      const data = JSON.stringify({
        template_id: process.env.MSG91_DLT_TEMPLATE_ID,
        short_url: "0",
        recipients: [
          {
            mobiles: `91${phone}`,
            VAR1: senderName || "Someone"
          }
        ]
      });
  
      const req = https.request(options, res => {
        let body = "";
        res.on("data", chunk => body += chunk);
        res.on("end", () => resolve(body));
      });
  
      req.on("error", reject);
      req.write(data);
      req.end();
  
    });
  }

  function sendCallSMS(phone, type) {
    return new Promise((resolve, reject) => {
  
      const templateId =
        type === "video"
          ? process.env.MSG91_VIDEO_CALL_TEMPLATE_ID
          : process.env.MSG91_VOICE_CALL_TEMPLATE_ID;
  
      const options = {
        method: "POST",
        hostname: "control.msg91.com",
        path: "/api/v5/flow/",
        headers: {
          authkey: process.env.MSG91_AUTH_KEY,
          "Content-Type": "application/json"
        }
      };
  
      const data = JSON.stringify({
        template_id: templateId,
        short_url: "0",
        recipients: [
          {
            mobiles: `91${phone}`
          }
        ]
      });
  
      const req = https.request(options, res => {
        let body = "";
        res.on("data", chunk => body += chunk);
        res.on("end", () => {
          console.log("MSG91 response:", body);
          resolve(body);
        });
      });
  
      req.on("error", reject);
      req.write(data);
      req.end();
    });
  }
  
  


function sendMSG91OTP(phone) {
  return new Promise((resolve, reject) => {
    const options = {
      method: "POST",
      hostname: "control.msg91.com",
      path: `/api/v5/otp?mobile=91${phone}&authkey=${process.env.MSG91_AUTH_KEY}&template_id=${process.env.MSG91_TEMPLATE_ID}`,
      headers: {
        "Content-Type": "application/json"
      },
      timeout: 5000
    };

    const req = https.request(options, res => {
      let data = "";
      res.on("data", chunk => (data += chunk));
      res.on("end", () => resolve(data));
    });

    req.on("error", reject);
    req.write(JSON.stringify({}));
    req.end();
  });
}

function verifyOTP(mobile, otp) {
    return new Promise((resolve, reject) => {
      const options = {
        method: "GET",
        hostname: "control.msg91.com",
        path: `/api/v5/otp/verify?otp=${otp}&mobile=${mobile}`,
        headers: {
          authkey: process.env.MSG91_AUTH_KEY
        }
      };
  
      const req = https.request(options, res => {
        let data = "";
        res.on("data", chunk => data += chunk);
        res.on("end", () => resolve(JSON.parse(data)));
      });
  
      req.on("error", reject);
      req.end();
    });
  }

  const otpLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 5,
    message: "Too many OTP requests. Try later."
  });

  app.get("/admin", isAdmin, async (req, res) => {
    try {
      const totalProfiles = await UserProfile.countDocuments();
  
      const incompleteProfiles = await UserProfile.countDocuments({
        $or: [
          { about: { $in: [null, ""] } },
          { expertise: { $size: 0 } },
          { interests: { $size: 0 } }
        ]
      });
  
      const activeMembers = await UserProfile.countDocuments({ isSubscribed: true });
      const inactiveMembers = await UserProfile.countDocuments({ isSubscribed: false });
  
      const verifiedProfiles = await UserProfile.countDocuments({
        isVerified: true
      });
  
      const pendingVerifications = await UserProfile.countDocuments({
        isVerified: false,
        govtIdImages: { $exists: true, $not: { $size: 0 } }
      });
      const notifications = await Notification
  .find()
  .sort({ createdAt: -1 })
  .limit(5)
  .lean();
      
  
      res.render("admin/dashboard.ejs", {
        totalProfiles,
        incompleteProfiles,
        activeMembers,
        inactiveMembers,
        verifiedProfiles,
        pendingVerifications,
        notifications
      });
  
    } catch (err) {
      console.error("Admin dashboard error:", err);
      res.status(500).send("Admin dashboard error");
    }
  });
  

  app.get("/admin/verifications", isAdmin, async (req, res) => {
    const profiles = await UserProfile.find({
      isVerified: false,
      govtIdImages: { $exists: true, $not: { $size: 0 } }
    }).lean();
    
  
    res.render("admin/verifications.ejs", { profiles });
  });
  
  

  app.get("/privacy-policy", (req, res) => {
    res.render("privacy.ejs");
  });
  app.get("/be-safe-online", (req, res) => {
    res.render("be-safe-online.ejs");
  });

  app.get("/terms-of-use", (req, res) => {
    res.render("terms-of-use.ejs");
  });

  app.get("/profiles", isAdmin, async (req, res) => {
    const profiles = await UserProfile.find()
      .select("first_name last_name phone email about expertise interests isSubscribed isVerified govtIdImages")
      .lean();

    // For each user, flag if they are involved in any unread conversation
    // (either as sender whose message the other hasn't read, or as receiver with unread messages)
    const phones = profiles.map(p => p.phone);
    const unreadChats = await Chat.aggregate([
      {
        $match: {
          isRead: false,
          $or: [
            { receiverPhone: { $in: phones } },
            { senderPhone: { $in: phones } }
          ]
        }
      },
      {
        $project: {
          phones: ["$senderPhone", "$receiverPhone"]
        }
      },
      { $unwind: "$phones" },
      { $match: { phones: { $in: phones } } },
      { $group: { _id: "$phones", count: { $sum: 1 } } }
    ]);
    const unreadMap = {};
    unreadChats.forEach(u => { unreadMap[u._id] = u.count; });
    const profilesWithUnread = profiles.map(p => ({
      ...p,
      unreadCount: unreadMap[p.phone] || 0
    }));

    res.render("admin/profiles.ejs", { profiles: profilesWithUnread });
  });


app.get("/profile/matchmaking", isLoggedIn, async (req, res) => {
  try {
    const userProfile = await UserProfile.findOne({
      phone: req.user.phone
    }).lean();

    res.render("matchmaking.ejs", {
      userProfile
    });
  } catch (err) {
    console.error("Matchmaking page error:", err);
    res.status(500).send("Unable to load matchmaking page");
  }
});


app.post("/profile/matchmaking", isLoggedIn, async (req, res) => {
  try {

    const cleanEnum = (val) =>
      val && val.trim() !== "" ? val.trim() : null;

    const matchmakingData = {
      maritalStatus: cleanEnum(req.body.maritalStatus),
      birth: {
        date: req.body.birthDate || null,
        time: req.body.birthTime || null,
        place: req.body.birthPlace || null
      },
      educationDetails: req.body.educationDetails || null,
      occupationDetails: req.body.occupationDetails || null,
      religion: req.body.religion || null,
      caste: req.body.caste || null,
      subCaste: req.body.subCaste || null,
      gotra: req.body.gotra || null,
      citizenship: req.body.citizenship || null,
      liveInCity: req.body.liveInCity || null,
      liveInState: req.body.liveInState || null,
      height: {
        feet: req.body.heightFeet || null,
        inches: req.body.heightInches || null
      },
      weight: req.body.weight || null,
      eatingHabit: cleanEnum(req.body.eatingHabit),
      smokingHabit: cleanEnum(req.body.smokingHabit),
      drinkingHabit: cleanEnum(req.body.drinkingHabit),
      fatherOccupation: req.body.fatherOccupation || null,
      motherOccupation: req.body.motherOccupation || null,
      brothers: req.body.brothers || null,
      sisters: req.body.sisters || null,
      familyAnnualIncome: req.body.familyIncome || null,
      otherInfo: req.body.otherInfo || null
    };

    await UserProfile.findOneAndUpdate(
      { phone: req.user.phone },
      { $set: { matchmaking: matchmakingData } },
      { new: true, upsert: true, runValidators: true }
    );
    

    res.redirect("/profile");

  } catch (err) {
    console.error("Matchmaking save error:", err);
    res.status(500).send("Failed to save matchmaking info");
  }
});

  
  
  app.post("/api/call/deduct-tokens", isLoggedIn, async (req, res) => {
    const { tokens } = req.body;
  
    const profile = await UserProfile.findOne({ phone: req.user.phone });
  
    if (!profile || profile.callTokens < tokens) {
      return res.json({ success: false });
    }
  
    profile.callTokens -= tokens;
    await profile.save();
  
    res.json({
      success: true,
      remaining: profile.callTokens
    });
  });
  
  app.get("/voice-call/:id", isLoggedIn, async (req, res) => {
    const receiver = await UserProfile.findById(req.params.id).lean();
    const myProfile = await UserProfile.findOne({ phone: req.user.phone });
    
    if (!hasPlanAccess(myProfile, VOICE_CALL_ENABLED_PLANS)) {
      return res.redirect("/pricing");
    }
    const duration = parseInt(req.query.duration) || 5;
  
    res.render("voice-call.ejs", {
      receiver,
      myProfile,
      duration
    });
  });
  

  app.get("/admin/profile/:id", isAdmin, async (req, res) => {
    try {
      const profile = await UserProfile.findById(req.params.id).lean();
      if (!profile) {
        return res.status(404).send("Profile not found");
      }
  
      // 🔥 Fetch phone from USERS collection
      const user = await User.findOne({ phone: profile.phone }).lean();

      // Count unread messages where this user is involved (sender or receiver)
      const unreadCount = profile.phone
        ? await Chat.countDocuments({
            isRead: false,
            $or: [
              { receiverPhone: profile.phone },
              { senderPhone: profile.phone }
            ]
          })
        : 0;

res.render("admin/profile_detail.ejs", {
  profile,
  phone: user?.phone || "Not available",
  unreadCount
});

  
    } catch (err) {
      console.error("Admin profile detail error:", err);
      res.status(500).send("Error loading profile");
    }
  });

// Admin – view all conversations for a profile
app.get("/admin/profile/:id/chats", isAdmin, async (req, res) => {
  try {
    const profile = await UserProfile.findById(req.params.id).lean();
    if (!profile) return res.status(404).send("Profile not found");

    const myPhone = profile.phone;

    // Get all messages where this user is sender or receiver
    const allMessages = await Chat.find({
      $or: [{ senderPhone: myPhone }, { receiverPhone: myPhone }]
    }).sort({ createdAt: -1 }).lean();

    // Build unique conversation partners
    const seen = new Map();
    for (const msg of allMessages) {
      const otherPhone = msg.senderPhone === myPhone ? msg.receiverPhone : msg.senderPhone;
      if (!seen.has(otherPhone)) {
        seen.set(otherPhone, msg);
      }
    }

    // Fetch profiles for each partner
    const conversations = [];
    for (const [otherPhone, lastMsg] of seen.entries()) {
      const otherProfile = await UserProfile.findOne({ phone: otherPhone })
        .select("first_name last_name image phone")
        .lean();
      conversations.push({
        otherPhone,
        otherProfile: otherProfile || { first_name: otherPhone, last_name: "", image: null, phone: otherPhone },
        lastMessage: lastMsg
      });
    }

    res.render("admin/chat_list.ejs", { profile, conversations });
  } catch (err) {
    console.error("Admin chat list error:", err);
    res.status(500).send("Error loading chat list");
  }
});

// Admin – view chat history between a profile and another phone
app.get("/admin/profile/:id/chats/:otherPhone", isAdmin, async (req, res) => {
  try {
    const profile = await UserProfile.findById(req.params.id).lean();
    if (!profile) return res.status(404).send("Profile not found");

    const myPhone = profile.phone;
    const otherPhone = req.params.otherPhone;

    const otherProfile = await UserProfile.findOne({ phone: otherPhone })
      .select("first_name last_name image phone")
      .lean();

    const messages = await Chat.find({
      $or: [
        { senderPhone: myPhone, receiverPhone: otherPhone },
        { senderPhone: otherPhone, receiverPhone: myPhone }
      ]
    }).sort({ createdAt: 1 }).lean();

    res.render("admin/chat_history.ejs", {
      profile,
      otherProfile: otherProfile || { first_name: otherPhone, last_name: "", image: null, phone: otherPhone },
      messages,
      myPhone
    });
  } catch (err) {
    console.error("Admin chat history error:", err);
    res.status(500).send("Error loading chat history");
  }
});
  
  




/* ===================== ROUTES ===================== */
app.get("/robots.txt", (req, res) => {
  res.type("text/plain").send([
    "User-agent: *",
    "Allow: /",
    "Disallow: /admin",
    "Disallow: /login",
    "Disallow: /profile/edit",
    `Sitemap: ${SITE_URL}/sitemap.xml`
  ].join("\n"));
});

app.get("/sitemap.xml", async (req, res) => {
  try {
    const staticPaths = [
      "/",
      "/pricing",
      "/about-us",
      "/contact-us",
      "/customer-support",
      "/privacy-policy",
      "/terms-of-use",
      "/be-safe-online",
      "/blogs"
    ];

    const [blogs, profiles] = await Promise.all([
      Blog.find().select("_id updatedAt createdAt").lean(),
      UserProfile.find().select("_id updatedAt createdAt").lean()
    ]);

    const urls = [
      ...staticPaths.map(path => ({
        loc: `${SITE_URL}${path === "/" ? "/" : path}`,
        lastmod: new Date()
      })),
      ...blogs.map(blog => ({
        loc: `${SITE_URL}/blogs/${blog._id}`,
        lastmod: blog.updatedAt || blog.createdAt || new Date()
      })),
      ...profiles.map(profile => ({
        loc: `${SITE_URL}/people/${profile._id}`,
        lastmod: profile.updatedAt || profile.createdAt || new Date()
      }))
    ];

    const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.map(url => `  <url>\n    <loc>${escapeXml(url.loc)}</loc>\n    <lastmod>${new Date(url.lastmod).toISOString()}</lastmod>\n  </url>`).join("\n")}\n</urlset>`;

    res.type("application/xml").send(xml);
  } catch (err) {
    console.error("Sitemap generation error:", err);
    res.status(500).type("text/plain").send("Unable to generate sitemap");
  }
});

app.get("/", async (req, res) => {
  try {

    const brides = await UserProfile.find({ gender: "Female" })
  .select("first_name last_name image isBlurred religion age")
  .sort({ createdAt: -1 })
  .limit(8)
  .lean();

const grooms = await UserProfile.find({ gender: "Male" })
  .select("first_name last_name image isBlurred religion age")
  .sort({ createdAt: -1 })
  .limit(8)
  .lean();

    res.render("home.ejs", {
      brides,
      grooms
    });

  } catch (err) {
    console.error("Home page error:", err);
    res.render("home.ejs", {
      brides: [],
      grooms: []
    });
  }
});

/* ---------- AUTH PAGES ---------- */
app.get("/login", (req, res) => res.render("login.ejs"));
app.get("/customer-support", (req, res) => {
  res.render("customer-support", {
    user: req.user || null,
    isAdmin: req.user?.isAdmin || false,
  });
});

app.get("/logout", (req, res, next) => {
    req.logout(function(err) {
      if (err) { return next(err); }
      res.redirect('/');
    });
  });

// 2. Send the OTP for Login
app.post("/send-otp",otpLimiter, async (req, res) => {
    const { phone } = req.body;
  
    if (!phone) {
      return res.status(400).json({ error: "Phone required" });
    }
  
    try {
      await sendMSG91OTP(phone);
  
      // ✅ STORE PHONE IN SESSION
      req.session.otpPhone = phone;
      req.session.otpVerified = false;
  
      console.log("OTP sent, session phone:", req.session.otpPhone);
  
      res.json({ success: true });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "OTP failed" });
    }
  });
// 3. Verify the OTP and log in
app.post("/verify-otp", async (req, res) => {
    const { otp } = req.body;
  
    // ✅ READ SAME KEY
    const phone = req.session.otpPhone;
  
    console.log("Verifying OTP for:", phone);
  
    if (!phone) {
      return res.status(400).json({ error: "Session expired. Please resend OTP." });
    }
  
    try {
      const result = await verifyOTP(`91${phone}`, otp);
  
      if (result.type !== "success") {
        return res.status(400).json({ error: "Invalid OTP" });
      }
  
      let user = await User.findOne({ phone });
  
      // ✅ AUTO CREATE USER IF NOT EXISTS (LOGIN + SIGNUP FLOW)
      if (!user) {
        user = await User.create({ phone });
      }
  
      req.login(user, err => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: "Login failed" });
        }
  
        // ✅ CLEAR OTP SESSION
        req.session.otpPhone = null;
        req.session.otpVerified = true;
  
        res.json({ success: true });
      });
  
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "OTP verification failed" });
    }
  });

  app.post("/api/messages/delete-call-message", isLoggedIn, async (req, res) => {
    try {
      const { messageId } = req.body;
  
      await Chat.findByIdAndDelete(messageId);
  
      res.json({ success: true });
  
    } catch (err) {
      console.error("Delete call message error:", err);
      res.status(500).json({ success: false });
    }
  });
  
  
 
//message routes
// app.get("/chat/:userId", isLoggedIn, async (req, res) => {
//   try {
//     const receiverProfile = await UserProfile.findById(req.params.userId).lean();
//     if (!receiverProfile) return res.status(404).send("User not found");

//     const messages = await Chat.find({
//       $or: [
//         { senderPhone: req.user.phone, receiverPhone: receiverProfile.phone },
//         { senderPhone: receiverProfile.phone, receiverPhone: req.user.phone }
//       ]
//     }).sort({ createdAt: 1 }).lean();

//     res.render("chat.ejs", {
//       receiverProfile,
//       receiverPhone: receiverProfile.phone, // Pass phone for socket matching
//       messages
//     });
//   } catch (err) {
//     res.status(500).send("Error");
//   }
// });

//calling 
app.get("/call/:id", isLoggedIn, async (req, res) => {
  const receiver = await UserProfile.findById(req.params.id).lean();
  const myProfile = await UserProfile.findOne({ phone: req.user.phone });
  
  if (!hasPlanAccess(myProfile, VIDEO_CALL_ENABLED_PLANS)) {
    return res.redirect("/pricing");
  }

  const isCaller = req.query.caller === "true";

  res.render("call.ejs", {
    receiver,
    myProfile,
    isCaller
  });
});

app.get("/login-password", (req, res) => {
  res.render("login_password.ejs");
});

import bcrypt from "bcrypt";

app.post("/login-password", async (req, res) => {
  const { phone, password } = req.body;

  const user = await User.findOne({ phone });

  if (!user || user.loginType !== "password") {
    return res.render("login_password.ejs", {
      error: "User not found"
    });
  }

  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
    return res.render("login_password.ejs", {
      error: "Invalid credentials"
    });
  }

  req.login(user, async (err) => {
    if (err) return res.status(500).send("Login failed");

    // 🔥 SAME FLOW AS OTP LOGIN
    let profile = await UserProfile.findOne({ phone });

    if (!profile) {
      return res.redirect("/profile/edit"); // ✅ correct for your app
    }

    if (!profile.isVerified) {
      return res.redirect("/profile/verify"); // ✅ you already have this route
    }

    res.redirect("/profile");
  });
});


app.post("/admin/create-makeup-user", isAdmin, async (req, res) => {
  const { phone, password, confirmPassword } = req.body;

  if (password !== confirmPassword) {
    return res.render("admin/create_makeup_user.ejs", {
      error: "Passwords do not match"
    });
  }

  const existing = await User.findOne({ phone });

  if (existing) {
    return res.render("admin/create_makeup_user.ejs", {
      error: "User already exists"
    });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  await User.create({
    phone,
    password: hashedPassword,
    loginType: "password"
  });

  res.render("admin/create_makeup_user.ejs", {
    success: "Makeup user created successfully"
  });
});


app.get("/admin/create-makeup-user", isAdmin, (req, res) => {
  res.render("admin/create_makeup_user.ejs");
});


// app.get("/chat/:userId", isLoggedIn, async (req, res) => {
//   try {
//     const receiverProfile = await UserProfile.findById(req.params.userId).lean();
//     if (!receiverProfile) return res.status(404).send("User not found");

//     const myProfile = await UserProfile.findOne({
//       phone: req.user.phone
//     }).lean();

//     const messages = await Chat.find({
//       $or: [
//         { senderPhone: req.user.phone, receiverPhone: receiverProfile.phone },
//         { senderPhone: receiverProfile.phone, receiverPhone: req.user.phone }
//       ]
//     }).sort({ createdAt: 1 }).lean();

//     await Chat.updateMany(
//       {
//         senderPhone: receiverProfile.phone,
//         receiverPhone: req.user.phone,
//         isRead: false
//       },
//       { $set: { isRead: true } }
//     );
    
//     // update navbar count
//     const unreadCount = await Chat.countDocuments({
//       receiverPhone: req.user.phone,
//       isRead: false
//     });
    
//     io.to(req.user.phone).emit("unread_count", unreadCount);
    

//     res.render("chat.ejs", {
//       receiverProfile,
//       receiverPhone: receiverProfile.phone, // Pass phone for socket matching
//       messages,
//       isSubscribed: myProfile?.isSubscribed === true
//     });
//   } catch (err) {
//     res.status(500).send("Error");
//   }
// });

app.get("/chat/:userId", isLoggedIn, async (req, res) => {
  try {

    const receiverProfile = await UserProfile.findById(req.params.userId).lean();
    if (!receiverProfile) return res.status(404).send("User not found");

    const myProfile = await UserProfile.findOne({
      phone: req.user.phone
    }).lean();

    // 🔐 ONLY STANDARD PLAN CAN CHAT
    if (!hasPlanAccess(myProfile, CHAT_ENABLED_PLANS)) {
      return res.redirect("/pricing");
    }

    const myPhone = req.user.phone;
    const receiverPhone = receiverProfile.phone;

    const roomId = [myPhone, receiverPhone].sort().join("_");

    const messages = await Chat.find({
      $or: [
        { senderPhone: myPhone, receiverPhone },
        { senderPhone: receiverPhone, receiverPhone: myPhone }
      ]
    }).sort({ createdAt: 1 }).lean();

    // Mark all unread messages from this sender as read
    await Chat.updateMany(
      { senderPhone: receiverPhone, receiverPhone: myPhone, isRead: false },
      { $set: { isRead: true } }
    );

    // Emit updated unread count to the user's room
    const unreadCount = await Chat.countDocuments({
      receiverPhone: myPhone,
      isRead: false
    });
    io.to(myPhone).emit("unread_count", unreadCount);

    res.render("chat.ejs", {
      receiverProfile,
      receiverPhone,
      messages,
      roomId
    });

  } catch (err) {
    console.error("CHAT ROUTE ERROR:", err);
    res.status(500).send("Error loading chat");
  }
});

app.post("/profile/toggle-blur", isLoggedIn, async (req, res) => {
  try {
    const profile = await UserProfile.findOne({ phone: req.user.phone });

    profile.isBlurred = !profile.isBlurred;

    await profile.save();

    res.json({ success: true, isBlurred: profile.isBlurred });

  } catch (err) {
    console.error("Blur toggle error:", err);
    res.status(500).json({ success: false });
  }
});

app.get("/api/messages/:userId", isLoggedIn, async (req, res) => {
  const receiverId = req.params.userId;
  const senderId = req.user._id;

  const messages = await Chat.find({
    $or: [
      { senderId: senderId, receiverId: receiverId },
      { senderId: receiverId, receiverId: senderId }
    ]
  }).sort({ createdAt: 1 }).lean();

  res.json(messages);
});

app.post("/api/messages/send", isLoggedIn, async (req, res) => {
  try {
    const { receiverId, message } = req.body;
    const senderPhone = req.user.phone;

    // 1. Find the receiver's profile
    // 1. Find the receiver's profile
const receiverProfile = await UserProfile.findById(receiverId).lean();

if (!receiverProfile || !receiverProfile.phone) {
  return res.status(400).json({ error: "Receiver phone not found" });
}

const receiverPhone = receiverProfile.phone;

    if (!receiverProfile || !receiverProfile.phone) {
      return res.status(400).json({ error: "Receiver phone not found" });
    }

// 🔐 Check subscription
const senderProfile = await UserProfile.findOne({ phone: senderPhone });

const isStandardUser =
  senderProfile?.isSubscribed &&
  senderProfile?.subscriptionPlan === "standard";

// If standard plan → skip restriction



    // 2. Save to Database
    // 2. Save to Database
const chatMsg = await Chat.create({
  senderPhone,
  receiverPhone,
  message,
  isRead: false
});

// 3. BROADCAST via Socket
io.to(receiverPhone).emit("receive message", {
  senderPhone: senderPhone,
  message: message,
  createdAt: chatMsg.createdAt
});

// Check if receiver is offline
const sockets = await io.in(receiverPhone).fetchSockets();

if (sockets.length === 0) {

  try {

    const senderProfile = await UserProfile.findOne({ phone: senderPhone });

    await sendNewMessageSMS(
      receiverPhone,
      senderProfile?.first_name || "Someone"
    );

    console.log("📩 DLT SMS sent to", receiverPhone);

  } catch (err) {
    console.error("SMS sending failed:", err);
  }

}
    const unreadCount = await Chat.countDocuments({
      receiverPhone,
      isRead: false
    });

    io.to(receiverPhone).emit("unread_count", unreadCount);

    // 4. Send success back to the person who sent it
    res.json({ success: true, message: chatMsg });

  } catch (err) {
    console.error("Chat Error:", err);
    res.status(500).json({ error: "Failed to send message" });
  }
});



// app.get("/inbox", isLoggedIn, async (req, res) => {
//   const myPhone = req.user.phone;
  

//   const messages = await Chat.find({
//     $or: [{ senderPhone: myPhone }, { receiverPhone: myPhone }]
//   }).sort({ createdAt: -1 }).lean();

//   const conversationsMap = new Map();

//   for (let msg of messages) {
//     const otherPhone = msg.senderPhone === myPhone ? msg.receiverPhone : msg.senderPhone;
//     if (!conversationsMap.has(otherPhone)) {
//       conversationsMap.set(otherPhone, msg);
//     }
//   }

//   const conversations = [];
//   for (let [phone, lastMessage] of conversationsMap) {
//     const profile = await UserProfile.findOne({ phone }).lean();
//     if (profile) {
//       conversations.push({ user: profile, lastMessage });
//     }
//   }
//   io.to(myPhone).emit("unread_count", 0);
//   res.render("inbox.ejs", { conversations });
// });

//new inbox route 
app.get("/inbox", isLoggedIn, async (req, res) => {
  const myPhone = req.user.phone;

  const messages = await Chat.find({
    $or: [{ senderPhone: myPhone }, { receiverPhone: myPhone }]
  }).sort({ createdAt: -1 }).lean();

  const conversationsMap = new Map();

  for (let msg of messages) {
    const otherPhone =
      msg.senderPhone === myPhone ? msg.receiverPhone : msg.senderPhone;

    if (!conversationsMap.has(otherPhone)) {
      conversationsMap.set(otherPhone, {
        lastMessage: msg,
        hasUnread: msg.receiverPhone === myPhone && msg.isRead === false
      });
    }
  }

  const conversations = [];
  for (let [phone, data] of conversationsMap) {
    const profile = await UserProfile.findOne({ phone }).lean();
    if (profile) {
      conversations.push({
        user: profile,
        lastMessage: data.lastMessage,
        hasUnread: data.hasUnread
      });
    }
  }

  res.render("inbox.ejs", { conversations });
});





// Mark all messages from a sender as read (called when user is on chat page and receives a live message)
app.post("/api/messages/mark-read", isLoggedIn, async (req, res) => {
  try {
    const { senderPhone } = req.body;
    const myPhone = req.user.phone;

    await Chat.updateMany(
      { senderPhone, receiverPhone: myPhone, isRead: false },
      { $set: { isRead: true } }
    );

    const unreadCount = await Chat.countDocuments({
      receiverPhone: myPhone,
      isRead: false
    });

    // Emit updated count so the badge on this tab updates
    io.to(myPhone).emit("unread_count", unreadCount);

    res.json({ success: true, unreadCount });
  } catch (err) {
    console.error("Mark read error:", err);
    res.status(500).json({ success: false });
  }
});

app.get("/api/unread-count", isLoggedIn, async (req, res) => {
  try {
    const count = await Chat.countDocuments({
      receiverPhone: req.user.phone,
      isRead: false
    });

    res.json({ count });
  } catch (err) {
    console.error("Unread count error:", err);
    res.status(500).json({ count: 0 });
  }
});




// Show form
app.get("/admin/create-user-full", isAdmin, (req, res) => {
  res.render("admin/create_user_full.ejs");
});

// Handle submit
app.post("/admin/create-user-full", isAdmin, (req, res) => {

  const uploadMiddleware = upload.fields([
    { name: "image", maxCount: 1 },
    { name: "coverImage", maxCount: 1 },
    { name: "photos", maxCount: 6 }
  ]);

  uploadMiddleware(req, res, async function (err) {

    // 🔥 HANDLE MULTER ERRORS PROPERLY
    if (err) {
      if (err.code === "LIMIT_FILE_SIZE") {
        return res.status(400).render("admin/upload_error.ejs", {
          message: "Image too large. Maximum allowed size is 5MB."
        });
      }

      return res.status(400).render("admin/upload_error.ejs", {
        message: "File upload failed. Please try again."
      });
    }

    try {

      const clean = (v) => (v && v.trim() !== "" ? v.trim() : null);

      const {
        phone,
        username,
        first_name,
        last_name,
        gender,
        Education,
        age,
        address,
        work,
        about,
        expertise,
        interests,

        subscriptionPlan,
        callTokens,
        isVerified,

        maritalStatus,
        birthDate,
        birthTime,
        birthPlace,
        educationDetails,
        occupationDetails,
        religion,
        caste,
        subCaste,
        gotra,
        citizenship,
        liveInCity,
        liveInState,
        heightFeet,
        heightInches,
        weight,
        eatingHabit,
        smokingHabit,
        drinkingHabit,
        fatherOccupation,
        motherOccupation,
        brothers,
        sisters,
        familyAnnualIncome,
        otherInfo

      } = req.body;

      if (!phone) {
        return res.status(400).send("Phone is required");
      }

      // ✅ CHECK DUPLICATE PROFILE
      const exists = await UserProfile.findOne({ phone });
      if (exists) {
        return res.status(400).send("Profile already exists with this phone number");
      }

      // ✅ ENSURE LOGIN USER EXISTS
      let user = await User.findOne({ phone });
      if (!user) {
        user = await User.create({ phone });
      }

      // ✅ SUBSCRIPTION LOGIC
      const plan = normalizeSubscriptionPlan(subscriptionPlan);

      let isSubscribed = false;
      let subscriptionStartedAt = null;
      let subscriptionExpiresAt = null;

      if (plan) {
        isSubscribed = true;
        subscriptionStartedAt = new Date();
        subscriptionExpiresAt = new Date();
        subscriptionExpiresAt.setMonth(subscriptionExpiresAt.getMonth() + 1);
      }

      // ✅ HANDLE IMAGE UPLOADS
      const profileImage = req.files?.image?.[0]?.path || "";
      const coverImage = req.files?.coverImage?.[0]?.path || "";
      const photos = req.files?.photos
        ? req.files.photos.map(f => f.path)
        : [];

      // ✅ MATCHMAKING OBJECT
      const matchmaking = {
        maritalStatus: clean(maritalStatus),

        birth: {
          date: birthDate ? new Date(birthDate) : null,
          time: clean(birthTime),
          place: clean(birthPlace)
        },

        educationDetails: clean(educationDetails),
        occupationDetails: clean(occupationDetails),

        religion: clean(religion),
        caste: clean(caste),
        subCaste: clean(subCaste),
        gotra: clean(gotra),

        citizenship: clean(citizenship),
        liveInCity: clean(liveInCity),
        liveInState: clean(liveInState),

        height: {
          feet: heightFeet ? Number(heightFeet) : null,
          inches: heightInches ? Number(heightInches) : null
        },

        weight: weight ? Number(weight) : null,

        eatingHabit: clean(eatingHabit),
        smokingHabit: clean(smokingHabit),
        drinkingHabit: clean(drinkingHabit),

        fatherOccupation: clean(fatherOccupation),
        motherOccupation: clean(motherOccupation),

        brothers: brothers ? Number(brothers) : null,
        sisters: sisters ? Number(sisters) : null,

        familyAnnualIncome: clean(familyAnnualIncome),
        otherInfo: clean(otherInfo)
      };

      // ✅ CREATE PROFILE
      const newProfile = await UserProfile.create({

        username: clean(username),
        first_name: clean(first_name) || "",
        last_name: clean(last_name) || "",
        phone: phone.toString(),

        gender: clean(gender),
        Education: clean(Education),
        age: age ? Number(age) : null,
        address: clean(address),
        work: clean(work),

        image: profileImage,
        coverImage,
        photos,

        about: clean(about),

        expertise: expertise
          ? expertise.split(",").map(x => x.trim()).filter(Boolean)
          : [],

        interests: interests
          ? interests.split(",").map(x => x.trim()).filter(Boolean)
          : [],

        isSubscribed,
        subscriptionPlan: plan,
        subscriptionStartedAt,
        subscriptionExpiresAt,

        callTokens: callTokens ? Number(callTokens) : 0,

        isVerified: isVerified === "true",
        verifiedAt: isVerified === "true" ? new Date() : null,
        verifiedByAdmin: isVerified === "true" ? req.user._id : null,

        matchmaking

      });

      // ✅ SUCCESS PAGE
      res.render("admin/profile_created.ejs", {
        profile: newProfile
      });

    } catch (error) {
      console.error("Admin create full user error:", error);
      res.status(500).send("Failed to create user");
    }

  });

});


//blogig request




app.get("/blogs", async (req, res) => {
  try {
    const blogs = await Blog.find().sort({ createdAt: -1 }).lean();
    res.render("blogs/index.ejs", { blogs });
  } catch (err) {
    console.error(err);
    res.status(500).send("Failed to load blogs");
  }
});

// 📖 Single blog page (PUBLIC)
app.get("/blogs/:id", async (req, res) => {
  try {
    const blog = await Blog.findById(req.params.id).lean();
    if (!blog) return res.status(404).send("Blog not found");
    const cleanContent = (blog.content || "").replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
    const blogSummary = cleanContent.slice(0, 120);
    res.locals.seo = buildSeo(req, {
      title: `${blog.title} | Shaadiwali Blog`,
      description: "Learn how to create an attractive matrimonial profile and improve match responses with expert tips from Shaadiwali.",
      canonicalPath: `/blogs/${blog._id}`,
      ogType: "article",
      ogImage: blog.coverImage || DEFAULT_OG_IMAGE,
      schema: [{
        "@context": "https://schema.org",
        "@type": "BlogPosting",
        headline: blog.title,
        description: blogSummary || "Shaadiwali matrimonial advice and relationship guidance.",
        image: blog.coverImage || DEFAULT_OG_IMAGE,
        author: {
          "@type": "Organization",
          name: blog.author || "Shaadiwali Team"
        },
        datePublished: blog.createdAt,
        dateModified: blog.updatedAt || blog.createdAt,
        mainEntityOfPage: `${SITE_URL}/blogs/${blog._id}`
      }]
    });
    res.render("blogs/show.ejs", { blog });
  } catch (err) {
    res.status(500).send("Error loading blog");
  }
});

// ✍️ Admin – New Blog Form
app.get("/admin/blogs/new", isAdmin, (req, res) => {
  res.render("blogs/new.ejs");
});


// ✍️ Admin – Create Blog
app.post("/admin/blogs", isAdmin, upload.single("coverImage"), async (req, res) => {
  try {
    const blogData = {
      title: req.body.title,
      content: req.body.content,
      author: req.user?.phone || "Shaadiwali Team",
    };

    if (req.file) {
      blogData.coverImage = req.file.path; // Cloudinary URL
    }

    await Blog.create(blogData);
    res.redirect("/blogs");
  } catch (err) {
    console.error(err);
    res.status(500).send("Failed to create blog");
  }
});
// 🗑️ Admin – Delete Blog
app.post("/admin/blogs/:id/delete", isAdmin, async (req, res) => {
  try {
    await Blog.findByIdAndDelete(req.params.id);
    res.redirect("/blogs");
  } catch (err) {
    console.error(err);
    res.status(500).send("Failed to delete blog");
  }
});

// 🗑️ ADMIN – Delete Profile
app.post("/admin/profile/:id/delete", isAdmin, async (req, res) => {
  try {
    const profile = await UserProfile.findById(req.params.id);

    if (!profile) {
      return res.status(404).send("Profile not found");
    }

    // Optional: delete linked user account too
    await User.deleteOne({ phone: profile.phone });

    await UserProfile.findByIdAndDelete(req.params.id);

    res.redirect("/profiles");
  } catch (err) {
    console.error("Delete profile error:", err);
    res.status(500).send("Failed to delete profile");
  }
});

app.get("/admin/profile/:id/edit", isAdmin, async (req, res) => {
  try {
    const profile = await UserProfile.findById(req.params.id).lean();

    if (!profile) {
      return res.status(404).send("Profile not found");
    }

    res.render("admin/edit_profile.ejs", {
      profile
    });

  } catch (err) {
    console.error("Admin edit page error:", err);
    res.status(500).send("Error loading edit page");
  }
});
app.post(
  "/admin/profile/:id/edit",
  isAdmin,
  upload.fields([
    { name: "image", maxCount: 1 },
    { name: "coverImage", maxCount: 1 }
  ]),
  async (req, res) => {

    try {

      const profileData = {
        first_name: req.body.first_name,
        last_name: req.body.last_name,
        age: req.body.age || null,
        gender: req.body.gender,
        address: req.body.address,
        work: req.body.work,
        Education: req.body.Education,
        about: req.body.about,
        expertise: req.body.expertise
          ? req.body.expertise.split(",").map(e => e.trim())
          : [],
        interests: req.body.interests
          ? req.body.interests.split(",").map(i => i.trim())
          : []
      };

      // image updates
      if (req.files?.image?.length) {
        profileData.image = req.files.image[0].path;
      }

      if (req.files?.coverImage?.length) {
        profileData.coverImage = req.files.coverImage[0].path;
      }

      await UserProfile.findByIdAndUpdate(
        req.params.id,
        { $set: profileData },
        { new: true }
      );

      res.redirect(`/admin/profile/${req.params.id}`);

    } catch (err) {
      console.error("Admin update error:", err);
      res.status(500).send("Failed to update profile");
    }

  }
);
app.get("/admin/profile/:id/matchmaking/edit", isAdmin, async (req, res) => {
  try {
    const profile = await UserProfile.findById(req.params.id).lean();

    if (!profile) {
      return res.status(404).send("Profile not found");
    }

    res.render("admin/edit_matchmaking.ejs", {
      profile
    });

  } catch (err) {
    console.error("Admin matchmaking edit page error:", err);
    res.status(500).send("Error loading matchmaking editor");
  }
});
app.post("/admin/profile/:id/matchmaking/edit", isAdmin, async (req, res) => {

  try {

    const clean = (v) => (v && v.trim() !== "" ? v.trim() : null);

    const matchmakingData = {

      maritalStatus: clean(req.body.maritalStatus),

      birth: {
        date: req.body.birthDate ? new Date(req.body.birthDate) : null,
        time: clean(req.body.birthTime),
        place: clean(req.body.birthPlace)
      },

      educationDetails: clean(req.body.educationDetails),
      occupationDetails: clean(req.body.occupationDetails),

      religion: clean(req.body.religion),
      caste: clean(req.body.caste),
      subCaste: clean(req.body.subCaste),
      gotra: clean(req.body.gotra),

      citizenship: clean(req.body.citizenship),
      liveInCity: clean(req.body.liveInCity),
      liveInState: clean(req.body.liveInState),

      height: {
        feet: req.body.heightFeet ? Number(req.body.heightFeet) : null,
        inches: req.body.heightInches ? Number(req.body.heightInches) : null
      },

      weight: req.body.weight ? Number(req.body.weight) : null,

      eatingHabit: clean(req.body.eatingHabit),
      smokingHabit: clean(req.body.smokingHabit),
      drinkingHabit: clean(req.body.drinkingHabit),

      fatherOccupation: clean(req.body.fatherOccupation),
      motherOccupation: clean(req.body.motherOccupation),

      brothers: req.body.brothers ? Number(req.body.brothers) : null,
      sisters: req.body.sisters ? Number(req.body.sisters) : null,

      familyAnnualIncome: clean(req.body.familyAnnualIncome),

      otherInfo: clean(req.body.otherInfo)

    };

    await UserProfile.findByIdAndUpdate(
      req.params.id,
      { $set: { matchmaking: matchmakingData } },
      { new: true }
    );

    res.redirect(`/admin/profile/${req.params.id}`);

  } catch (err) {
    console.error("Admin matchmaking update error:", err);
    res.status(500).send("Failed to update matchmaking");
  }

});




// --- PROTECTED ROUTES ---

// People & Profile Routes
// app.get("/people", async (req, res) => {
//     try {
//         const { name, address, minAge, maxAge, gender, interest } = req.query;

      
//         // Base filter
// let filter = {};

// // Exclude logged-in user ONLY if logged in
// if (req.user?.phone) {
//     filter.phone = { $ne: req.user.phone };
// }

          

//         // 🔍 Name filter (first or last name)
//         if (name) {
//             filter.$or = [
//                 { first_name: { $regex: name, $options: "i" } },
//                 { last_name: { $regex: name, $options: "i" } }
//             ];
//         }

//         // 📍 Address filter
//         if (address) {
//             filter.address = { $regex: address, $options: "i" };
//         }

//         // ⚧ Gender filter
//         if (gender) {
//           filter.gender = { $regex: `^${gender}$`, $options: "i" };
//         }

//         // 🎂 Age range filter
//         if (minAge || maxAge) {
//             filter.age = {};
//             if (minAge) filter.age.$gte = Number(minAge);
//             if (maxAge) filter.age.$lte = Number(maxAge);
//         }

//         // 🎯 Interest filter (array-safe)
//         if (interest) {
//             filter.interests = { $in: [new RegExp(interest, "i")] };
//         }

//         // 🔎 Query database
//         const people = await UserProfile.find(filter).lean();

//         // Render page
//         res.render("people", {
//             people,
//             query: req.query
//         });

//     } catch (err) {
//         console.error("Error fetching filtered people:", err);
//         res.status(500).send("Error loading people list.");
//     }
// });

app.get("/people", async (req, res) => {
  try {
    const { name, address, state, minAge, maxAge, gender, interest } = req.query;

    let filter = {};

    // Exclude logged-in user
    if (req.user?.phone) {
      filter.phone = { $ne: req.user.phone };
    }

    // Filters
    if (name) {
      filter.$or = [
        { first_name: { $regex: name, $options: "i" } },
        { last_name: { $regex: name, $options: "i" } }
      ];
    }

    if (address) {
      filter.address = { $regex: address, $options: "i" };
    }
    if (state) {
      filter.address = { $regex: state, $options: "i" };
    }

    if (gender) {
      filter.gender = { $regex: `^${gender}$`, $options: "i" };
    }

    if (minAge || maxAge) {
      filter.age = {};
      if (minAge) filter.age.$gte = Number(minAge);
      if (maxAge) filter.age.$lte = Number(maxAge);
    }

    if (interest) {
      filter.interests = { $in: [new RegExp(interest, "i")] };
    }

    // 🔐 SUBSCRIPTION LOGIC
    let limit = 20; // free users

if (req.user) {
  const myProfile = await UserProfile.findOne({ phone: req.user.phone });

  if (myProfile?.isSubscribed) {

    const plan = myProfile.subscriptionPlan;

    if (plan === "Basic") {
      limit = 50;
    }

    else if (plan === "standard") {
      limit = 100;
    }

    else if (
      plan === "Premium" ||
      plan==="Elite"||
      plan === "Elite-3" ||
      plan === "Elite-6" ||
      plan === "NRI-3" ||
      plan === "NRI-6"
    ) {
      limit = null; 
    }
  }
}

    // 🔎 Fetch profiles
    let query = UserProfile.find(filter).sort({ createdAt: -1 });

    if (limit !== null) {
      query = query.limit(limit);
    }

    const people = await query.lean();

    res.render("people", {
      people,
      query: req.query,
      limit
    });

  } catch (err) {
    console.error("People fetch error:", err);
    res.status(500).send("Error loading profiles");
  }
});



app.get("/people/:id", async (req, res) => {
  try {
    const person = await UserProfile.findById(req.params.id);
    if (!person) return res.status(404).send("Person not found");
    const personObject = person.toObject();
    const displayName = `${personObject.first_name || ""} ${personObject.last_name || ""}`.trim() || "Member";
    const canonicalPath = `/people/${personObject._id}`;
    const canonicalUrl = `${SITE_URL}${canonicalPath}`;

    res.locals.seo = buildSeo(req, {
      title: `${personObject.first_name || displayName}'s Matrimonial Profile | Shaadiwali`,
      description: `View ${displayName}'s verified matrimonial profile on Shaadiwali. Explore preferences, background details, and compatibility for marriage.`,
      canonicalPath,
      ogType: "profile",
      ogImage: personObject.image || DEFAULT_OG_IMAGE,
      schema: [buildPersonSchema(personObject, canonicalUrl)]
    });

    // 🔍 Track profile view (only if logged in & not self)
    if (req.user && req.user.phone && req.user.phone !== person.phone) {
      const alreadyViewed = person.profileViews?.some(
        v => v.viewerPhone === req.user.phone
      );

      if (alreadyViewed) {
        // Update the timestamp of the existing entry — no duplicate, no count bump
        await UserProfile.updateOne(
          { _id: person._id, "profileViews.viewerPhone": req.user.phone },
          { $set: { "profileViews.$.viewedAt": new Date() } }
        );
      } else {
        // First time this person has viewed — add entry and increment count
        await UserProfile.updateOne(
          { _id: person._id },
          {
            $inc: { profileViewsCount: 1 },
            $push: {
              profileViews: {
                viewerPhone: req.user.phone,
                viewedAt: new Date()
              }
            }
          }
        );
      }
    }

    res.render("profiledetail.ejs", {
      person: personObject,
      user: req.user || null,
      userProfile: res.locals.userProfile || null
    });

  } catch (err) {
    console.error(err);
    res.status(500).send("Error loading profile");
  }
});


//verigy batch
app.get("/profile/verify", isLoggedIn, (req, res) => {
  res.render("verify.ejs");
});
app.post(
  "/profile/verify",
  isLoggedIn,
  upload.single("govtId"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).send("File required");
      }

      await UserProfile.findOneAndUpdate(
        { phone: req.user.phone },
        {
          $push: {
            govtIdImages: req.file.path
          },
          verificationRequestedAt: new Date(),
          isVerified: false
        }
      );

      res.redirect("/profile");
    } catch (err) {
      console.error("Verification upload error:", err);
      res.status(500).send("Verification failed");
    }
  }
);
app.post("/admin/verify/:id", isAdmin, async (req, res) => {
  const profile = await UserProfile.findById(req.params.id);

if (!profile) {
  return res.status(404).send("Profile not found");
}

if (profile.isVerified) {
  return res.redirect("/admin/profile/" + req.params.id); // already verified
}

  await UserProfile.findByIdAndUpdate(req.params.id, {
    isVerified: true,
    verifiedAt: new Date(),
    verifiedByAdmin: req.user._id
  });

  res.redirect("/admin/profile/" + req.params.id);
});


// Profile Routes
app.get("/profile", isLoggedIn, async (req, res) => {
  const userProfile = await UserProfile.findOne({
    phone: req.user.phone
  }).lean();

  if (!userProfile) {
    return res.redirect("/profile/edit");
  }

  // 🔥 Populate viewer names (deduplicate by viewerPhone, keep latest viewedAt)
  if (userProfile.profileViews?.length) {
    // Deduplicate: keep only the most recent entry per viewerPhone
    const deduped = new Map();
    for (const v of userProfile.profileViews) {
      const existing = deduped.get(v.viewerPhone);
      if (!existing || new Date(v.viewedAt) > new Date(existing.viewedAt)) {
        deduped.set(v.viewerPhone, v);
      }
    }
    const uniqueViews = Array.from(deduped.values());

    const phones = uniqueViews.map(v => v.viewerPhone);

    const viewers = await UserProfile.find({ phone: { $in: phones } })
      .select("first_name last_name phone image")
      .lean();

    const viewerMap = {};
    viewers.forEach(v => {
      viewerMap[v.phone] = v;
    });

    userProfile.profileViews = uniqueViews.map(v => ({
      ...v,
      viewer: viewerMap[v.viewerPhone] || null
    }));
  }

  res.render("profile.ejs", { userProfile });
});

  
  app.get("/about-us", (req, res) => {
    res.render("about.ejs");
  });
  

app.get("/profile/edit", isLoggedIn, (req, res) => {
  try {
      const userProfile = res.locals.userProfile;
      res.render("edit_profile.ejs", { user: req.user, userProfile: userProfile });
  } catch (err)
 {
      console.error("Error rendering edit profile page:", err);
      res.status(500).send("An error occurred loading edit page.");
  }
});


app.post(
  "/profile",
  isLoggedIn,
  upload.fields([
    { name: "image", maxCount: 1 },
    { name: "coverImage", maxCount: 1 }
  ]),
  async (req, res) => {
    try {
      const profileData = {
        first_name: req.body.first_name,
        last_name: req.body.last_name,
        age: req.body.age || null,
        gender: req.body.gender,
        address: req.body.address,
        work: req.body.work,
        Education: req.body.Education,
        about: req.body.about,
        expertise: req.body.expertise
          ? req.body.expertise.split(",").map(e => e.trim())
          : [],
        interests: req.body.interests
          ? req.body.interests.split(",").map(i => i.trim())
          : [],
        phone: req.user.phone
      };
      
      // ✅ CHECK IF PROFILE EXISTS
      let existingProfile = await UserProfile.findOne({ phone: req.user.phone });
      
      // 🎯 APPLY FREE PLAN ONLY FIRST TIME
      if (!existingProfile) {
        profileData.isSubscribed = true;
        profileData.subscriptionPlan = "Basic";
        profileData.subscriptionStartedAt = new Date();
      
        let expires = new Date();
        expires.setDate(expires.getDate() + 11); // ✅ 11 days free
      
        profileData.subscriptionExpiresAt = expires;
      }

      // ✅ ALWAYS USE .path (multer-cloudinary)
      if (req.files?.image?.length) {
        profileData.image = req.files.image[0].path;
      }

      if (req.files?.coverImage?.length) {
        profileData.coverImage = req.files.coverImage[0].path;
      }

      const updatedProfile = await UserProfile.findOneAndUpdate(
        { phone: req.user.phone },
        profileData,            // ❗ NO $set
        { upsert: true, new: true }
      );

      console.log("✅ Profile saved:", updatedProfile);

      res.status(200).json({ success: true });
    } catch (err) {
      console.error("❌ Profile save failed:", err);
      res.status(500).json({ success: false, error: err.message });
    }
  }
);

//tokens

app.get("/tokens", isLoggedIn, (req, res) => {
  res.render("tokens.ejs");
});
app.post("/tokens/verify", isLoggedIn, async (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature, tokens } = req.body;

  const generatedSignature = crypto
    .createHmac("sha256", process.env.Razor_key_secret)
    .update(`${razorpay_order_id}|${razorpay_payment_id}`)
    .digest("hex");

  if (generatedSignature !== razorpay_signature) {
    return res.status(400).json({ success: false });
  }

  await UserProfile.findOneAndUpdate(
    { phone: req.user.phone },
    { $inc: { callTokens: tokens } }
  );

  res.json({ success: true });
});


  
app.get("/profile/photos", isLoggedIn, (req, res) => {
  res.render("upload_photos.ejs");
});
app.post(
  "/profile/photos",
  isLoggedIn,
  upload.array("photos", 6), // allow up to 6 photos at once
  async (req, res) => {
    try {
      const photoUrls = req.files.map(file => file.path);

      await UserProfile.findOneAndUpdate(
        { phone: req.user.phone },
        { $push: { photos: { $each: photoUrls } } },
        { new: true }
      );

      res.redirect("/profile");
    } catch (err) {
      console.error("❌ Photo upload failed:", err);
      res.status(500).send("Photo upload failed");
    }
  }
);

app.post("/profile/photos/delete", isLoggedIn, async (req, res) => {
  try {
    const { photoUrl } = req.body;

    if (!photoUrl) {
      return res.redirect("/profile");
    }

    // 1️⃣ Remove from MongoDB
    await UserProfile.findOneAndUpdate(
      { phone: req.user.phone },
      { $pull: { photos: photoUrl } }
    );

    // 2️⃣ Remove from Cloudinary
    const publicId = photoUrl
      .split("/")
      .slice(-1)[0]
      .split(".")[0];

    await cloudinary.uploader.destroy(
      `shaadiwali_profiles/${publicId}`
    );

    res.redirect("/profile");

  } catch (err) {
    console.error("❌ Photo delete failed:", err);
    res.status(500).send("Failed to delete photo");
  }
});


app.get("/contact-us", (req, res) => {
  res.render("contact");
});
app.post("/profile/delete", async (req, res) => {
  try {
    const userId = req.user._id;

    // delete profile
    await UserProfile.deleteOne({ phone: req.user.phone });

    // optional: delete user also
    await User.deleteOne({ _id: userId });

    // destroy session
    req.logout(() => {
      req.session.destroy(() => {
        res.redirect("/");
      });
    });

  } catch (err) {
    console.error(err);
    res.send("Error deleting profile");
  }
});
//choosing
app.get("/choosing",isLoggedIn, async (req, res) => {
  const myPhone = req.user.phone;

  const myProfile = await UserProfile.findOne({ phone: myPhone });

  const excludedIds = [
    myProfile?._id,
    ...(myProfile?.likes || [])
  ];

  // get one random profile user hasn’t liked yet
  const profile = await UserProfile.findOne({
    _id: { $nin: excludedIds }
  });

  if (!profile) {
    return res.render("choosing.ejs", { profile: null });
  }

  res.render("choosing.ejs", { profile });
});

app.post("/choosing/like", isLoggedIn, async (req, res) => {
  const myProfile = await UserProfile.findOne({ phone: req.user.phone });

  await UserProfile.updateOne(
    { _id: myProfile._id },
    { $addToSet: { likes: req.body.profileId } }
  );

  res.json({ success: true });
});
app.post("/choosing/dislike", isLoggedIn, async (req, res) => {
  res.json({ success: true });
});

app.get("/liked", isLoggedIn, async (req, res) => {
  const myProfile = await UserProfile
    .findOne({ phone: req.user.phone })
    .populate("likes")
    .lean();

  res.render("liked.ejs", { profiles: myProfile.likes });
});

app.post("/admin/profile/:id/update-membership", async (req, res) => {
  try {
    const { subscriptionPlan, callTokens, duration } = req.body;

    const profile = await UserProfile.findById(req.params.id);

    if (!profile) return res.redirect("/profiles");

    // ✅ UPDATE PLAN
    profile.subscriptionPlan = subscriptionPlan || null;
    profile.isSubscribed = !!subscriptionPlan;

    // ✅ UPDATE TOKENS
    if (callTokens !== undefined) {
      profile.callTokens = parseInt(callTokens);
    }

    // ✅ UPDATE DATES
    if (subscriptionPlan) {
      const start = new Date();
      const expiry = new Date();

      expiry.setMonth(expiry.getMonth() + (parseInt(duration) || 1));

      profile.subscriptionStartedAt = start;
      profile.subscriptionExpiresAt = expiry;
    } else {
      profile.subscriptionStartedAt = null;
      profile.subscriptionExpiresAt = null;
    }

    await profile.save();

    res.redirect(`/admin/profile/${profile._id}`);

  } catch (err) {
    console.error(err);
    res.send("Error updating membership");
  }
});

// --- Payment Routes (Unchanged) ---
app.get("/pricing", (req, res) => {
    res.render("pricing.ejs");
});

const razorpay = new Razorpay({
    key_id: process.env.Razor_key_id,
    key_secret: process.env.Razor_key_secret,
});

app.post("/create-order", isLoggedIn, async (req, res) => {
    try {
      const { amount } = req.body;
      if (!amount || isNaN(amount) || amount <= 0) {
          return res.status(400).send("Invalid amount");
      }
      const order = await razorpay.orders.create({
        amount: Math.round(amount * 100),
        currency: "INR",
        payment_capture: 1,
      });

      res.json({ orderId: order.id });
    } catch (err) {
      console.error("Error creating Razorpay order:", err);
      res.status(500).send("Error creating order");
    }
});

app.post("/verify-payment", isLoggedIn, async (req, res) => {
  try {
    const {
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature,
      plan
    } = req.body;

    // ✅ Verify Razorpay signature
    const generatedSignature = crypto
      .createHmac("sha256", process.env.Razor_key_secret)
      .update(`${razorpay_order_id}|${razorpay_payment_id}`)
      .digest("hex");

    if (generatedSignature !== razorpay_signature) {
      return res.status(400).json({ success: false });
    }

    // ✅ PLAN DURATION LOGIC
    let expiresAt = new Date();

    switch (plan) {
      case "Basic":
    expiresAt.setDate(expiresAt.getDate() + 11); 
    break;
      case "standard":
      case "Premium":
        expiresAt.setMonth(expiresAt.getMonth() + 1);
        break;

      case "Elite-3":
      case "NRI-3":
        expiresAt.setMonth(expiresAt.getMonth() + 3);
        break;

      case "Elite-6":
      case "NRI-6":
        expiresAt.setMonth(expiresAt.getMonth() + 6);
        break;

      default:
        return res.status(400).json({ success: false });
    }

    await UserProfile.findOneAndUpdate(
      { phone: req.user.phone },
      {
        isSubscribed: true,
        subscriptionPlan: plan,
        subscriptionStartedAt: new Date(),
        subscriptionExpiresAt: expiresAt
      },
      { new: true, upsert: true }
    );
    await Notification.create({
      type: "purchase",
      message: `New ${plan} plan purchased`,
      userPhone: req.user.phone,
      plan
    });
    
    // 🔥 REAL-TIME ALERT
    io.emit("admin_notification", {
      message: `💰 New ${plan} purchase by ${req.user.phone}`
    });

    res.json({ success: true });

  } catch (err) {
    console.error("Payment verify error:", err);
    res.status(500).json({ success: false });
  }
});




// --- SERVER LISTEN ---
server.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
