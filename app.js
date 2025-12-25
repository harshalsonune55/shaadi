

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

const upload = multer({ storage });





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
app.set("view engine", "ejs");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

/* ===================== SESSION ===================== */
app.use(
    session({
      name: "shaadi.sid",
      secret: process.env.SESSION_SECRET || "shaadi-super-secret-key",
      resave: false,
      saveUninitialized: true,   // ✅ MUST BE TRUE FOR OTP
      cookie: {
        httpOnly: true,
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
  



  io.on("connection", (socket) => {
    // Now joining by phone instead of ID
    socket.on("join user room", (phone) => {
      if (phone) {
        socket.join(phone.toString());
        console.log(`📥 Joined room: ${phone}`);
      }
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
      }
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
  
      const activeMembers = await UserProfile.countDocuments({
        isSubscribed: true
      });
  
      const inactiveMembers = await UserProfile.countDocuments({
        isSubscribed: false
      });
  
      res.render("admin/dashboard.ejs", {
        totalProfiles,
        incompleteProfiles,
        activeMembers,
        inactiveMembers
      });
  
    } catch (err) {
      console.error("Admin dashboard error:", err);
      res.status(500).send("Admin dashboard error");
    }
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
app.get("/signup", (req, res) => res.render("signup.ejs"));
app.get("/logout", (req, res, next) => {
    req.logout(function(err) {
      if (err) { return next(err); }
      res.redirect('/');
    });
  });

// 2. Send the OTP for Login
app.post("/send-otp", async (req, res) => {
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
app.get("/chat/:userId", isLoggedIn, async (req, res) => {
  try {
    const receiverProfile = await UserProfile.findById(req.params.userId).lean();
    if (!receiverProfile) return res.status(404).send("User not found");

    const messages = await Chat.find({
      $or: [
        { senderPhone: req.user.phone, receiverPhone: receiverProfile.phone },
        { senderPhone: receiverProfile.phone, receiverPhone: req.user.phone }
      ]
    }).sort({ createdAt: 1 }).lean();

    res.render("chat.ejs", {
      receiverProfile,
      receiverPhone: receiverProfile.phone, // Pass phone for socket matching
      messages
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
      message
    });

    // 3. BROADCAST via Socket
    // Use io.to() to send only to the receiver's room
    console.log(`📡 Broadcasting from ${senderPhone} to room: ${receiverPhone}`);
    
    io.to(receiverPhone).emit("receive message", {
      senderPhone: senderPhone,
      message: message,
      createdAt: chatMsg.createdAt
    });

    // 4. Send success back to the person who sent it
    res.json({ success: true, message: chatMsg });

  } catch (err) {
    console.error("Chat Error:", err);
    res.status(500).json({ error: "Failed to send message" });
  }
});



app.get("/inbox", isLoggedIn, async (req, res) => {
  const myPhone = req.user.phone;

  const messages = await Chat.find({
    $or: [{ senderPhone: myPhone }, { receiverPhone: myPhone }]
  }).sort({ createdAt: -1 }).lean();

  const conversationsMap = new Map();

  for (let msg of messages) {
    const otherPhone = msg.senderPhone === myPhone ? msg.receiverPhone : msg.senderPhone;
    if (!conversationsMap.has(otherPhone)) {
      conversationsMap.set(otherPhone, msg);
    }
  }

  const conversations = [];
  for (let [phone, lastMessage] of conversationsMap) {
    const profile = await UserProfile.findOne({ phone }).lean();
    if (profile) {
      conversations.push({ user: profile, lastMessage });
    }
  }
  res.render("inbox.ejs", { conversations });
});






// --- PROTECTED ROUTES ---

// People & Profile Routes
app.get("/people", async (req, res) => {
    try {
        const { name, address, minAge, maxAge, gender, interest } = req.query;

      
        // Base filter
let filter = {};

// Exclude logged-in user ONLY if logged in
if (req.user?.phone) {
    filter.phone = { $ne: req.user.phone };
}

          

        // 🔍 Name filter (first or last name)
        if (name) {
            filter.$or = [
                { first_name: { $regex: name, $options: "i" } },
                { last_name: { $regex: name, $options: "i" } }
            ];
        }

        // 📍 Address filter
        if (address) {
            filter.address = { $regex: address, $options: "i" };
        }

        // ⚧ Gender filter
        if (gender) {
          filter.gender = { $regex: `^${gender}$`, $options: "i" };
        }

        // 🎂 Age range filter
        if (minAge || maxAge) {
            filter.age = {};
            if (minAge) filter.age.$gte = Number(minAge);
            if (maxAge) filter.age.$lte = Number(maxAge);
        }

        // 🎯 Interest filter (array-safe)
        if (interest) {
            filter.interests = { $in: [new RegExp(interest, "i")] };
        }

        // 🔎 Query database
        const people = await UserProfile.find(filter).lean();

        // Render page
        res.render("people", {
            people,
            query: req.query
        });

    } catch (err) {
        console.error("Error fetching filtered people:", err);
        res.status(500).send("Error loading people list.");
    }
});


app.get("/people/:id", async (req, res) => {
    try {
        const person = await UserProfile.findById(req.params.id).lean(); // Use lean
        if (!person) return res.status(404).send("Person not found");
        res.render("profiledetail.ejs", { person, user: req.user || null, userProfile: res.locals.userProfile ||null });
    } catch (err) {
        console.error("Error fetching person details:", err);
        res.status(500).send("Error loading profile details");
    }
});

// Profile Routes
app.get("/profile", isLoggedIn, async (req, res) => {
    const userProfile = await UserProfile.findOne({
      phone: req.user.phone
    }).lean();
  
    if (!userProfile) {
      return res.redirect("/profile/edit");
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

app.get("/contact-us", (req, res) => {
  res.render("contact");
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
    const secret = process.env.Razor_key_secret;
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

    try {
        const shasum = crypto.createHmac("sha256", secret);
        shasum.update(`${razorpay_order_id}|${razorpay_payment_id}`);
        const generated_signature = shasum.digest("hex");

        if (generated_signature === razorpay_signature) {
          console.log("Payment verified successfully:", razorpay_payment_id);

          await UserProfile.findOneAndUpdate(
              { email: req.user.email },
              { isSubscribed: true },
              { new: true, upsert: true, setDefaultsOnInsert: true }
          );
          console.log(`User ${req.user.email} subscription status updated.`);

          res.json({ success: true });
        } else {
          console.error("Payment verification failed: Invalid signature");
          res.status(400).json({ success: false, message: "Invalid signature" });
        }
    } catch (error) {
        console.error("Error during payment verification or profile update:", error);
        res.status(500).json({ success: false, message: "Internal server error" });
    }
});


// --- SERVER LISTEN ---
server.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});






