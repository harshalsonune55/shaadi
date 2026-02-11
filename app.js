

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
    fileSize: 500 * 1024 
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

/* ===================== DB ===================== */
mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.error(err));

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
      // 📞 Incoming Call Notification
  socket.on("incoming_call", ({ to, from, callerName, callUrl }) => {
    if (!to) return;

    console.log(`📞 Incoming call from ${from} to ${to}`);

    // Send notification to receiver's personal room
    io.to(to.toString()).emit("incoming_call", {
      from,
      callerName,
      callUrl
    });
  });

  });
  




/* ===================== MSG91 OTP FUNCTION ===================== */


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

export function verifyOTP(mobile, otp) {
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

  //admin Routes 

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
      
  
      res.render("admin/dashboard.ejs", {
        totalProfiles,
        incompleteProfiles,
        activeMembers,
        inactiveMembers,
        verifiedProfiles,
        pendingVerifications
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
      .select("first_name last_name email about expertise interests isSubscribed")
      .lean();
  
    res.render("admin/profiles.ejs", { profiles });
  });

  //matchmaking 
  // Serve Matchmaking Form Page
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
      await UserProfile.findOneAndUpdate(
        { phone: req.user.phone },
        {
          matchmaking: {
            maritalStatus: req.body.maritalStatus,
            birth: {
              date: req.body.birthDate,
              time: req.body.birthTime,
              place: req.body.birthPlace
            },
            educationDetails: req.body.educationDetails,
            occupationDetails: req.body.occupationDetails,
            religion: req.body.religion,
            caste: req.body.caste,
            subCaste: req.body.subCaste,
            gotra: req.body.gotra,
            citizenship: req.body.citizenship,
            liveInCity: req.body.liveInCity,
            liveInState: req.body.liveInState,
            height: {
              feet: req.body.heightFeet,
              inches: req.body.heightInches
            },
            weight: req.body.weight,
            eatingHabit: req.body.eatingHabit || null,
smokingHabit: req.body.smokingHabit || null,
drinkingHabit: req.body.drinkingHabit || null,

            fatherOccupation: req.body.fatherOccupation,
            motherOccupation: req.body.motherOccupation,
            brothers: req.body.brothers,
            sisters: req.body.sisters,
            familyAnnualIncome: req.body.familyIncome,
            otherInfo: req.body.otherInfo
          }
        },
        { new: true, upsert: true }
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
  
  

  app.get("/admin/profile/:id", isAdmin, async (req, res) => {
    try {
      const profile = await UserProfile.findById(req.params.id).lean();
      if (!profile) {
        return res.status(404).send("Profile not found");
      }
  
      // 🔥 Fetch phone from USERS collection
      const user = await User.findOne({ phone: profile.phone }).lean();

res.render("admin/profile_detail.ejs", {
  profile,
  phone: user?.phone || "Not available"
});

  
    } catch (err) {
      console.error("Admin profile detail error:", err);
      res.status(500).send("Error loading profile");
    }
  });
  
  




/* ===================== ROUTES ===================== */
app.get("/", (req, res) => res.render("home.ejs"));

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

  if (!myProfile?.isSubscribed) {
    return res.redirect("/pricing");
  }

  const isCaller = true;
  

  res.render("call.ejs", {
    receiver,
    myProfile,
    isCaller
  });
});


app.get("/chat/:userId", isLoggedIn, async (req, res) => {
  try {
    const receiverProfile = await UserProfile.findById(req.params.userId).lean();
    if (!receiverProfile) return res.status(404).send("User not found");

    const myProfile = await UserProfile.findOne({
      phone: req.user.phone
    }).lean();

    const messages = await Chat.find({
      $or: [
        { senderPhone: req.user.phone, receiverPhone: receiverProfile.phone },
        { senderPhone: receiverProfile.phone, receiverPhone: req.user.phone }
      ]
    }).sort({ createdAt: 1 }).lean();

    await Chat.updateMany(
      {
        senderPhone: receiverProfile.phone,
        receiverPhone: req.user.phone,
        isRead: false
      },
      { $set: { isRead: true } }
    );
    
    // update navbar count
    const unreadCount = await Chat.countDocuments({
      receiverPhone: req.user.phone,
      isRead: false
    });
    
    io.to(req.user.phone).emit("unread_count", unreadCount);
    

    res.render("chat.ejs", {
      receiverProfile,
      receiverPhone: receiverProfile.phone, // Pass phone for socket matching
      messages,
      isSubscribed: myProfile?.isSubscribed === true
    });
  } catch (err) {
    res.status(500).send("Error");
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
    const receiverProfile = await UserProfile.findById(receiverId).lean();
    
    if (!receiverProfile || !receiverProfile.phone) {
      return res.status(400).json({ error: "Receiver phone not found" });
    }

    const receiverPhone = receiverProfile.phone;

    // 2. Save to Database
    const chatMsg = await Chat.create({
      senderPhone,
      receiverPhone,
      message,
      isRead: false
    });

    // 3. BROADCAST via Socket
    // Use io.to() to send only to the receiver's room
    console.log(`📡 Broadcasting from ${senderPhone} to room: ${receiverPhone}`);
    
    io.to(receiverPhone).emit("receive message", {
      senderPhone: senderPhone,
      message: message,
      createdAt: chatMsg.createdAt
    });
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
    const { name, address, minAge, maxAge, gender, interest } = req.query;

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
    let limit = 20; // default → FREE

    if (req.user) {
      const myProfile = await UserProfile.findOne({ phone: req.user.phone });

      if (myProfile?.isSubscribed) {
        const unlimitedPlans = [
          "standard",
          "Premium",
          "Elite-3",
          "Elite-6",
          "NRI-3",
          "NRI-6"
        ];
        
      
        if (myProfile.subscriptionPlan === "Basic") {
          limit = 50;
        } else if (myProfile.subscriptionPlan === "standard") {
          limit = 100;
        } else if (unlimitedPlans.includes(myProfile.subscriptionPlan)) {
          limit = 0; // unlimited
        }
      }
      
    }

    // 🔎 Fetch profiles
    let query = UserProfile.find(filter).sort({ createdAt: -1 });

    if (limit > 0) {
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

    // 🔍 Track profile view (only if logged in & not self)
    if (req.user && req.user.phone && req.user.phone !== person.phone) {
      await UserProfile.updateOne(
        { _id: person._id },
        {
          $inc: { profileViewsCount: 1 },
          $addToSet: {
            profileViews: {
              viewerPhone: req.user.phone,
              viewedAt: new Date()
            }
          }
          
        }
      );
    }

    res.render("profiledetail.ejs", {
      person: person.toObject(),
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
          govtIdImage: req.file.path,
          verificationRequestedAt: new Date()
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

  // 🔥 Populate viewer names
  if (userProfile.profileViews?.length) {
    const phones = userProfile.profileViews.map(v => v.viewerPhone);

    const viewers = await UserProfile.find({ phone: { $in: phones } })
      .select("first_name last_name phone image")
      .lean();

    const viewerMap = {};
    viewers.forEach(v => {
      viewerMap[v.phone] = v;
    });

    userProfile.profileViews = userProfile.profileViews.map(v => ({
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






