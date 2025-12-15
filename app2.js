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

configDotenv();
const app = express();
const server = createServer(app);
const PORT = process.env.PORT || 3000;

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
  if (req.user) {
    res.locals.userProfile = await UserProfile.findOne({ phone: req.user.phone });
  }
  next();
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

/* ===================== ROUTES ===================== */
app.get("/", (req, res) => res.render("home.ejs"));

/* ---------- AUTH PAGES ---------- */
app.get("/login", (req, res) => res.render("login.ejs"));
app.get("/signup", (req, res) => res.render("signup.ejs"));

/* ---------- SEND OTP (LOGIN + SIGNUP) ---------- */
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
  
  

/* ---------- VERIFY OTP ---------- */
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
  
  

/* ---------- LOGOUT ---------- */
app.get("/logout", (req, res) => {
  req.logout(() => res.redirect("/"));
});

/* ===================== PROTECTED ===================== */
app.get("/people", isLoggedIn, async (req, res) => {
  const people = await UserProfile.find({ phone: { $ne: req.user.phone } });
  res.render("people", { people, query: req.query });
});

app.get("/people/:id", isLoggedIn, async (req, res) => {
  const person = await UserProfile.findById(req.params.id);
  res.render("profiledetail.ejs", { person });
});

/* ---------- PROFILE ---------- */
app.get("/profile", isLoggedIn, async (req, res) => {
  const profile = await UserProfile.findOne({ phone: req.user.phone });
  if (!profile) return res.redirect("/profile/edit");
  res.render("profile.ejs", { userProfile: profile });
});

app.get("/profile/edit", isLoggedIn, async (req, res) => {
  const profile = await UserProfile.findOne({ phone: req.user.phone });
  res.render("edit_profile.ejs", { userProfile: profile });
});

app.post("/profile", isLoggedIn, async (req, res) => {
  await UserProfile.findOneAndUpdate(
    { phone: req.user.phone },
    req.body,
    { upsert: true }
  );
  res.redirect("/profile");
});

/* ===================== PAYMENTS ===================== */
const razorpay = new Razorpay({
  key_id: process.env.Razor_key_id,
  key_secret: process.env.Razor_key_secret
});

app.post("/create-order", isLoggedIn, async (req, res) => {
  const order = await razorpay.orders.create({
    amount: req.body.amount * 100,
    currency: "INR"
  });
  res.json(order);
});

app.post("/verify-payment", isLoggedIn, async (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
  const sign = crypto
    .createHmac("sha256", process.env.Razor_key_secret)
    .update(`${razorpay_order_id}|${razorpay_payment_id}`)
    .digest("hex");

  if (sign === razorpay_signature) {
    await UserProfile.updateOne(
      { phone: req.user.phone },
      { isSubscribed: true }
    );
    res.json({ success: true });
  } else {
    res.status(400).json({ success: false });
  }
});

/* ===================== SERVER ===================== */
server.listen(PORT, () =>
  console.log(`🚀 Server running on http://localhost:${PORT}`)
);
