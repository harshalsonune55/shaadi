// import express from 'express';
// const app = express();
// import { createServer } from 'http';
// import { Server } from 'socket.io';
// import { configDotenv } from 'dotenv';
// configDotenv();
// const PORT = process.env.PORT || 3000;
// import ejsmate from 'ejs-mate';
// import mongoose from 'mongoose';
// import session from "express-session";
// import passport from 'passport';
// import LocalStrategy from 'passport-local';

// // Models
// import User from './model/user.js';
// import UserProfile from './model/user.profile.js';
// import Chat from './model/chat.js';

// // Middleware
// import { isLoggedIn } from './middleware/auth.js'; 

// // Other imports
// import Razorpay from "razorpay";
// import crypto from "crypto";

// const server = createServer(app);
// const io = new Server(server);

// // --- DATABASE CONNECTION ---
// mongoose.connect(process.env.MONGO_URL, {
//     useNewUrlParser: true,
//     useUnifiedTopology: true
// }).then(() => console.log("Connected to MongoDB"))
//   .catch(err => console.error("Error connecting to MongoDB:", err));

// // --- APP CONFIGURATION ---
// app.engine('ejs', ejsmate);
// app.set('view engine', 'ejs');
// app.use(express.json());
// app.use(express.urlencoded({ extended: true }));
// app.use(express.static('public'));

// // --- SESSION AND AUTHENTICATION SETUP ---
// const sessionConfig = {
//     secret: process.env.SESSION_SECRET || "thisisnotagoodsecret",
//     resave: false,
//     saveUninitialized: true,
//     cookie: {
//         httpOnly: true,
//         // secure: true, // Enable this in production with HTTPS
//         expires: Date.now() + 1000 * 60 * 60 * 24 * 7,
//         maxAge: 1000 * 60 * 60 * 24 * 7
//     }
// };

// app.use(session(sessionConfig));

// app.use(passport.initialize());
// app.use(passport.session());

// // Configure Passport to use the LocalStrategy with 'email' as the username field
// passport.use(new LocalStrategy({ usernameField: 'email' }, User.authenticate()));

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

// // Middleware to make user info available in all templates
// app.use(async (req, res, next) => {
//   res.locals.user = req.user || null;
  
//   // If a user is logged in, find their detailed profile
//   if (req.user) {
//       // We find the profile by matching the email from the authenticated user
//       res.locals.userProfile = await UserProfile.findOne({ email: req.user.email });
//   } else {
//       res.locals.userProfile = null;
//   }
//   next();
// });

// // --- SOCKET.IO ---
// io.on('connection', (socket) => {
//   console.log('A user connected:', socket.id);

//   // User joins a specific chat room (for sending/receiving in chat room)
//   socket.on('join room', (room) => {
//     socket.join(room);
//     console.log(`User ${socket.id} joined chat room: ${room}`);
//   });

//   // User joins their own personal room (for inbox updates)
//   socket.on('join user room', (userId) => {
//     if (userId) {
//        socket.join(userId.toString());
//        console.log(`User ${socket.id} joined personal room: ${userId}`);
//     }
//   });

//   // This listener is not strictly needed if the POST route handles everything,
//   // but it's good to keep for potential future features.
//   socket.on('chat message', (data) => {
//     // console.log("Broadcasting message to room:", data.room);
//     // socket.to(data.room).emit('chat message', data);
//   });

//   socket.on('disconnect', () => {
//     console.log('User disconnected:', socket.id);
//   });
// });

// // --- ROUTES ---

// // Home Route
// app.get('/', (req, res) => {
//     res.render('home.ejs');
// });

// // Signup Routes
// app.get("/signup", (req, res) => {
//     res.render("signup.ejs");
// });

// app.post("/signup_user", async (req, res, next) => {
//   try {
//       const { fullname, email, password, confirm_password } = req.body;
//       if (password !== confirm_password) {
//           return res.render("signup", { error: "Passwords do not match" });
//       }
//       const user = new User({ email, fullname });
//       const registeredUser = await User.register(user, password);
//       req.login(registeredUser, err => {
//           if (err) return next(err);
//           res.redirect("/");
//       });
//   } catch (e) {
//       console.error("Error during signup:", e.message);
//       res.render("signup", { error: e.message });
//   }
// });

// // Login Routes
// app.get("/login", (req, res) => {
//     res.render("login.ejs");
// });

// // Use passport.authenticate() middleware for login
// app.post("/login_user", passport.authenticate("local", {
//   failureRedirect: "/login",
// }), (req, res) => {
//   const redirectUrl = req.session.returnTo || '/';
//   delete req.session.returnTo;
//   res.redirect(redirectUrl);
// });

// // Logout Route
// app.get("/logout", (req, res, next) => {
//     req.logout(function(err) {
//         if (err) { return next(err); }
//         res.redirect('/');
//     });
// });

// // People & Profile Routes
// app.get("/people", isLoggedIn, async(req, res) => {
//     const people = await UserProfile.find({});
//     res.render("people", { people, query: req.query });
// });

// app.get("/people/:id", isLoggedIn, async (req, res) => {
//     const person = await UserProfile.findById(req.params.id);
//     if (!person) return res.status(404).send("Person not found");
//     res.render("profiledetail.ejs", { person, user: req.user });
// });

// app.get("/profile", isLoggedIn, async (req, res) => {
//   try {
//       const userProfile = await UserProfile.findOne({ email: req.user.email });

//       if (userProfile) {
//           // If profile exists, show it
//           res.render("profile.ejs", { user: req.user, userProfile: userProfile });
//       } else {
//           // If no profile, redirect to the create/edit form
//           res.redirect("/profile/edit");
//       }
//   } catch (err) {
//       console.error("Error at /profile route:", err);
//       res.status(500).send("An error occurred.");
//   }
// });

// // RENDER EDIT/CREATE FORM
// app.get("/profile/edit", isLoggedIn, async (req, res) => {
//   try {
//       const userProfile = await UserProfile.findOne({ email: req.user.email });
//       // Render the form, passing existing profile data (or null if it's a new user)
//       res.render("edit_profile.ejs", { user: req.user, userProfile: userProfile });
//   } catch (err) {
//       console.error("Error rendering edit profile page:", err);
//       res.status(500).send("An error occurred.");
//   }
// });

// // HANDLE FORM SUBMISSION (CREATE or UPDATE)
// app.post("/profile", isLoggedIn, async (req, res) => {
//   try {
//       const profileData = {
//           first_name: req.body.first_name,
//           last_name: req.body.last_name,
//           age: req.body.age,
//           gender: req.body.gender,
//           address: req.body.address,
//           work: req.body.work,
//           Education: req.body.Education,
//           image: req.body.image,
//           email: req.user.email, // Always link to the logged-in user's email
//           username: req.user.username
//       };

//       // Find profile by email and update it, OR create it if it doesn't exist (upsert: true)
//       await UserProfile.findOneAndUpdate(
//           { email: req.user.email },
//           profileData,
//           { new: true, upsert: true, setDefaultsOnInsert: true }
//       );

//       res.redirect("/profile"); // Redirect back to the view profile page
//   } catch (err) {
//       console.error("Error saving profile:", err);
//       res.status(500).send("An error occurred while saving the profile.");
//   }
// });

// // INBOX ROUTE
// app.get("/inbox", isLoggedIn, async (req, res) => {
//   try {
//       const userId = req.user._id;

//       // 1. Find all messages involving the current user
//       const messages = await Chat.find({
//           $or: [{ senderId: userId }, { receiverId: userId }]
//       }).sort({ createdAt: -1 });

//       // 2. Group messages by conversation partner
//       const conversationsMap = new Map();
//       messages.forEach(msg => {
//           // Determine the "other person" in the chat
//           const otherUserId = msg.senderId.toString() === userId.toString() ? msg.receiverId.toString() : msg.senderId.toString();
          
//           // If we haven't seen this conversation yet, add it with the latest message
//           if (!conversationsMap.has(otherUserId)) {
//               conversationsMap.set(otherUserId, msg);
//           }
//       });

//       // 3. Fetch profile details and format the data for the template
//       const conversations = [];
//       for (const [otherUserId, lastMessage] of conversationsMap.entries()) {
//           const participantProfile = await UserProfile.findById(otherUserId);
//           if (participantProfile) {
//               conversations.push({
//                   participant: participantProfile,
//                   lastMessage: lastMessage
//               });
//           }
//       }
      
//       // Sort conversations to show the most recent ones first
//       conversations.sort((a, b) => b.lastMessage.createdAt - a.lastMessage.createdAt);

//       res.render("inbox", { conversations });
//   } catch (err) {
//       console.error("Error fetching inbox:", err);
//       res.status(500).send("Error loading your inbox.");
//   }
// });

// // CHAT ROOM ROUTE (Renders the page)
// app.get("/chat/:personId", isLoggedIn, async (req, res) => {
//     try {
//         const { personId } = req.params;
//         const person = await UserProfile.findById(personId);
//         if (!person) return res.status(404).send("Person not found");
//         res.render("chat_room.ejs", { person, currentUser: req.user });
//     } catch (error) {
//         console.error("Error loading chat room:", error);
//         res.status(500).send("Error loading chat room");
//     }
// });

// // CHAT HISTORY API ROUTE (Fetches message data)
// app.get("/api/chat/:personId", isLoggedIn, async (req, res) => {
//     try { 
//         const userId = req.user?._id;
//         const personId = req.params.personId; 

//         console.log("--- Fetching Chat History ---");
//         console.log("Current User ID (userId):", userId, `(Type: ${typeof userId})`);
//         console.log("Other Person ID (personId):", personId, `(Type: ${typeof personId})`);

//         if (!userId || !personId) {
//             console.error("Missing userId or personId");
//             return res.status(400).json({ error: "Invalid user IDs provided" });
//         }

//         const userIdString = userId.toString();
//         const personIdString = personId.toString();
//         console.log("Querying with User ID:", userIdString);
//         console.log("Querying with Person ID:", personIdString);
        
//         const messages = await Chat.find({
//             $or: [
//                 { senderId: userIdString, receiverId: personIdString },
//                 { senderId: personIdString, receiverId: userIdString },
//             ]
//         }).sort({ createdAt: 1 });

//         console.log(`Found ${messages.length} messages between ${userIdString} and ${personIdString}`); 

//         res.json(messages);

//     } catch (error) { 
//         console.error("Error in /api/chat/:personId:", error);
//         res.status(500).json({ error: "Failed to fetch chat history due to server error" });
//     }
// });

// // SEND MESSAGE ROUTE (Handles saving and emitting)
// // This is the correct, complex route you intended to use.
// app.post("/chat/send", isLoggedIn, async (req, res) => {
//   const { receiverId, message } = req.body;
//   const senderId = req.user?._id;

//   if (!senderId || !receiverId || !message) {
//       console.error("Missing senderId, receiverId, or message in /chat/send");
//       return res.status(400).json({ error: "Missing required fields" });
//   }

//   try {
//       // Save the message
//       const chatMsg = new Chat({ senderId, receiverId, message });
//       await chatMsg.save();
//       console.log("Message saved:", chatMsg._id);

//       // --- Function to get participant data (handles missing profiles) ---
//       async function getParticipantData(userId) {
//           const userProfile = await UserProfile.findById(userId).lean(); // Use .lean() for plain JS object
//           if (userProfile) {
//               return {
//                   _id: userProfile._id,
//                   first_name: userProfile.first_name || 'User',
//                   last_name: userProfile.last_name || '',
//                   image: userProfile.image || `https://ui-avatars.com/api/?name=${userProfile.first_name || 'U'}`
//               };
//           }
//           // Fallback to basic User data
//           const basicUser = await User.findById(userId).lean();
//           if (basicUser) {
//                console.warn(`UserProfile not found for ID: ${userId}, using basic User data for inbox update.`);
//               return {
//                   _id: basicUser._id,
//                   first_name: basicUser.fullname?.split(' ')[0] || 'User',
//                   last_name: basicUser.fullname?.split(' ').slice(1).join(' ') || '',
//                   image: `https://ui-avatars.com/api/?name=${basicUser.fullname || 'U'}`
//               };
//           }
//           // Final fallback
//           console.error(`Could not find any user data for ID: ${userId} during inbox update emission.`);
//           return {
//               _id: userId, // Still need the ID
//               first_name: 'Unknown',
//               last_name: 'User',
//               image: 'https://ui-avatars.com/api/?name=?'
//           };
//       }
//       // --- End function ---

//       // Get data for both participants
//       const senderData = await getParticipantData(senderId);
//       const receiverData = await getParticipantData(receiverId);

//       // Prepare data structure for the event (matches structure from /inbox route)
//       const lastMessageData = {
//            message: chatMsg.message,
//            createdAt: chatMsg.createdAt // Ensure timestamp is included
//       };

//       const updateDataForReceiver = {
//           participant: senderData,       // Receiver sees the sender as participant
//           lastMessage: lastMessageData
//       };
//       const updateDataForSender = {
//           participant: receiverData,      // Sender sees the receiver as participant
//           lastMessage: lastMessageData
//       };

//       // Emit 'update inbox' event
//       io.to(receiverId.toString()).emit('update inbox', updateDataForReceiver);
//       console.log(`Emitted 'update inbox' to room ${receiverId.toString()} with data:`, JSON.stringify(updateDataForReceiver));

//       io.to(senderId.toString()).emit('update inbox', updateDataForSender);
//       console.log(`Emitted 'update inbox' to room ${senderId.toString()} with data:`, JSON.stringify(updateDataForSender));

//      // Also emit the message to the specific chat room for live chat updates
//      const roomId = [senderId.toString(), receiverId.toString()].sort().join('-');
//       io.to(roomId).emit('chat message', {
//           room: roomId,
//           message: chatMsg.message,
//           senderId: chatMsg.senderId.toString(), // Ensure IDs are strings here too
//           createdAt: chatMsg.createdAt
//       });
//       console.log(`Emitted 'chat message' to room ${roomId}`);

//       // Respond to the POST request
//       res.status(200).json({ success: true, message: "Message saved and emitted." });

//   } catch (error) {
//        console.error("Error sending chat message:", error);
//        res.status(500).json({ success: false, message: "Failed to send message." });
//   }
// });

// // *** THE DUPLICATE ROUTE WAS HERE AND HAS BEEN DELETED ***

// // Pricing and Payment Routes
// app.get("/pricing", (req, res) => {
//     res.render("pricing.ejs");
// });

// const razorpay = new Razorpay({
//     key_id: process.env.Razor_key_id,
//     key_secret: process.env.Razor_key_secret,
// });

// app.post("/create-order", isLoggedIn, async (req, res) => {
//     try {
//       const { amount } = req.body;
//       const order = await razorpay.orders.create({
//         amount: amount * 100, 
//         currency: "INR",
//         payment_capture: 1,
//       });
  
//       res.json({ orderId: order.id });
//     } catch (err) {
//       console.error(err);
//       res.status(500).send("Error creating order");
//     }
// });

// app.post("/verify-payment", isLoggedIn, (req, res) => {
//     const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
  
//     const hmac = crypto.createHmac("sha256", process.env.Razor_key_secret);
//     hmac.update(razorpay_order_id + "|" + razorpay_payment_id);
//     const generated_signature = hmac.digest("hex");
  
//     if (generated_signature === razorpay_signature) {
//       console.log("Payment verified:", razorpay_payment_id);
//       res.json({ success: true });
//     } else {
//       res.status(400).json({ success: false, message: "Invalid signature" });
//     }
// });


// // --- SERVER LISTEN ---
// server.listen(PORT, () => {
//     console.log(`Server is running on http://localhost:${PORT}`);
// });

import express from 'express';
const app = express();
import { createServer } from 'http';
import { configDotenv } from 'dotenv';
configDotenv();
const PORT = process.env.PORT || 3000;
import ejsmate from 'ejs-mate';
import mongoose from 'mongoose';
import session from "express-session";
import passport from 'passport';
import LocalStrategy from 'passport-local';
import GoogleStrategy from 'passport-google-oauth20';
import cors from 'cors';

// --- Import Twilio ---
import twilio from 'twilio';

// --- Import Models ---
import User from './model/user.js';
import UserProfile from './model/user.profile.js';
// We no longer need the Chat model

// Middleware
import { isLoggedIn } from './middleware/auth.js';

// Other imports
import Razorpay from "razorpay";
import crypto from "crypto";

// --- Initialize Twilio Client ---
const twilioAccountSid = process.env.TWILIO_ACCOUNT_SID;
const twilioAuthToken = process.env.TWILIO_AUTH_TOKEN;
const twilioPhoneNumber = process.env.TWILIO_PHONE_NUMBER;
let twilioClient;

if (twilioAccountSid && twilioAuthToken && twilioPhoneNumber) {
    twilioClient = twilio(twilioAccountSid, twilioAuthToken);
    console.log("Twilio client initialized.");
} else {
    console.error("Twilio credentials (SID, TOKEN, or PHONE_NUMBER) missing in .env! OTP login will not function.");
}


const server = createServer(app);

// --- DATABASE CONNECTION ---
// Removed deprecated options for new Mongoose versions
mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log("Connected to MongoDB"))
  .catch(err => console.error("Error connecting to MongoDB:", err));

// --- APP CONFIGURATION ---
app.engine('ejs', ejsmate);
app.set('view engine', 'ejs');

app.use(cors({
    origin: 'http://localhost:5173', // Adjust this
    credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// --- SESSION AND AUTHENTICATION SETUP ---
const sessionConfig = {
    secret: process.env.SESSION_SECRET || "fallback-secret-key",
    resave: false,
    saveUninitialized: true, // Save session even if not modified (needed for storing OTP temporarily)
    cookie: {
        httpOnly: true,
        expires: Date.now() + 1000 * 60 * 60 * 24 * 7,
        maxAge: 1000 * 60 * 60 * 24 * 7
    }
};

app.use(session(sessionConfig)); // Session must be before Passport
app.use(passport.initialize());
app.use(passport.session());

// --- PASSPORT STRATEGIES ---
passport.use(new LocalStrategy({ usernameField: 'email' }, User.authenticate()));
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ googleId: profile.id });
        if (user) { return done(null, user); }

        user = await User.findOne({ email: profile.emails[0].value });
        if (user) {
            user.googleId = profile.id;
            await user.save();
            return done(null, user);
        }

        const newUser = new User({
            email: profile.emails[0].value,
            fullname: profile.displayName,
            googleId: profile.id
            // phone will be null
        });
        await newUser.save();
        return done(null, newUser);

    } catch (err) {
        return done(err, false);
    }
  }
));

// --- PASSPORT SERIALIZE/DESERIALIZE ---
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err, null);
    }
});

// --- GLOBAL MIDDLEWARE (res.locals) ---
app.use(async (req, res, next) => {
    // No PubNub keys needed
    res.locals.user = req.user || null;
    if (req.user) {
        res.locals.userProfile = await UserProfile.findOne({ email: req.user.email }).lean();
    } else {
        res.locals.userProfile = null;
    }
    next();
  });


// --- ROUTES ---

// Home Route
app.get('/', (req, res) => {
    res.render('home.ejs');
});

// --- AUTH ROUTES ---

// Signup Routes
app.get("/signup", (req, res) => {
    res.render("signup.ejs");
});

// --- NEW SIGNUP OTP ROUTES ---

// 1. Send OTP for Signup
app.post("/signup-send-otp", async (req, res) => {
    const { fullname, email, phone, password } = req.body; // Expecting phone with +91

    if (!twilioClient) {
        return res.status(500).json({ error: "OTP service is not configured." });
    }

    try {
        // --- Check if email or phone already exist ---
        const phoneDigits = phone.replace('+91', '');
        const existingUser = await User.findOne({ $or: [{ email: email }, { phone: phoneDigits }] });
        if (existingUser) {
            return res.status(409).json({ error: "An account with that email or phone number already exists." });
        }

        // --- Generate OTP ---
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expires = Date.now() + 5 * 60 * 1000; // 5 minutes expiry

        // --- Store temporary signup data in session ---
        req.session.signupData = { fullname, email, phone: phoneDigits, password }; // Store 10 digit phone
        req.session.signupOtp = otp;
        req.session.signupOtpExpires = expires;
        req.session.signupPhone = phone; // Store full +91 number for display/verification

        // --- Send OTP via Twilio ---
        await twilioClient.messages.create({
            body: `Your Wanderlust signup OTP is: ${otp}`,
            from: twilioPhoneNumber,
            to: phone
        });

        res.status(200).json({ success: true, message: "OTP sent successfully." });

    } catch (err) {
        console.error("Error sending signup OTP:", err);
        if (err.code === 21211) { // Twilio error for invalid number
            return res.status(400).json({ error: "Invalid phone number format." });
        }
        res.status(500).json({ error: "Failed to send OTP." });
    }
});

// 2. Verify OTP and Create User
app.post("/signup-verify-otp", async (req, res) => {
    const { otp } = req.body;

    // --- Validate session data ---
    if (
        !req.session.signupData ||
        !req.session.signupOtp ||
        !req.session.signupOtpExpires ||
        req.session.signupOtp !== otp
    ) {
        return res.status(400).json({ error: "Invalid or incorrect OTP." });
    }

    // --- Check expiry ---
    if (Date.now() > req.session.signupOtpExpires) {
        // Clear temporary data
        req.session.signupData = null;
        req.session.signupOtp = null;
        req.session.signupOtpExpires = null;
        req.session.signupPhone = null;
        return res.status(400).json({ error: "OTP has expired. Please start signup again." });
    }

    // --- OTP is valid! Create the user ---
    try {
        const { fullname, email, phone, password } = req.session.signupData;
        const user = new User({ email, fullname, phone });

        const registeredUser = await User.register(user, password);

        // Clear temporary session data *after* successful registration
        req.session.signupData = null;
        req.session.signupOtp = null;
        req.session.signupOtpExpires = null;
        req.session.signupPhone = null;

        // --- Log the new user in ---
        req.login(registeredUser, (err) => {
            if (err) {
                console.error("Error logging in user after signup OTP verification:", err);
                // User was created but login failed - maybe redirect to login page?
                return res.status(500).json({ error: "Account created, but auto-login failed. Please log in manually." });
            }
            // Send success response (frontend will redirect)
            res.status(200).json({ success: true, message: "Account created successfully." });
        });

    } catch (e) {
        console.error("Error registering user after OTP verification:", e.message);
        // Handle potential errors during User.register (though existence check was done before)
         if (e.name === 'UserExistsError' || (e.code === 11000)) {
             return res.status(409).json({ error: "An account with that email or phone number already exists." });
        }
        res.status(500).json({ error: "Failed to create account." });
    }
});


// --- OLD SIGNUP ROUTE (No longer needed, comment out or delete) ---
/*
app.post("/signup_user", async (req, res, next) => {
  // ... old code ...
});
*/

// --- LOGIN ROUTES ---

// Original Login Page
app.get("/login", (req, res) => {
    res.render("login.ejs");
});

// Original Login Post Route (Email/Password)
app.post("/login_user", passport.authenticate("local", {
  failureRedirect: "/login",
}), (req, res) => {
  const redirectUrl = req.session.returnTo || '/';
  delete req.session.returnTo;
  res.redirect(redirectUrl);
});

// Google Auth Routes
app.get('/auth/google',
  passport.authenticate('google', {
    scope: ['profile', 'email']
  }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  async (req, res) => {
    const redirectUrl = req.session.returnTo || '/';
    delete req.session.returnTo;
    res.redirect(redirectUrl);
  });

// Logout Route
app.get("/logout", (req, res, next) => {
    req.logout((err) => {
        if (err) { return next(err); }
        res.redirect('/');
    });
});


// --- OTP LOGIN ROUTES ---

// 1. Render the OTP login page
app.get("/login-otp", (req, res) => {
    res.render("login-otp.ejs");
});

// 2. Send the OTP for Login
app.post("/send-otp", async (req, res) => {
    const { phone } = req.body; // Expecting phone with country code, e.g., +919876543210

    if (!twilioClient) {
        return res.status(500).json({ error: "OTP service is not configured." });
    }

    // Check if user with this phone exists
    try {
        const phoneDigits = phone.replace('+91', '');

        const user = await User.findOne({ phone: phoneDigits });
        if (!user) {
            return res.status(404).json({ error: "No user found with this phone number." });
        }

        // Generate a 6-digit OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        // Set expiry time (e.g., 5 minutes)
        const expires = Date.now() + 5 * 60 * 1000;

        // Store OTP and phone in session FOR LOGIN
        req.session.loginOtp = otp; // Use different session key names
        req.session.loginOtpExpires = expires;
        req.session.loginPhone = phone; // Store the full +91 number

        // Send the OTP via Twilio
        await twilioClient.messages.create({
            body: `Your Wanderlust login OTP is: ${otp}`,
            from: twilioPhoneNumber,
            to: phone
        });

        res.status(200).json({ success: true, message: "OTP sent successfully." });

    } catch (err) {
        console.error("Error sending login OTP:", err);
        // Twilio errors might be specific
        if (err.code === 21211) {
            return res.status(400).json({ error: "Invalid phone number." });
        }
        res.status(500).json({ error: "Failed to send OTP." });
    }
});

// 3. Verify the OTP and log in
app.post("/verify-otp", async (req, res) => {
    const { phone, otp } = req.body;

    // Check if LOGIN session data exists and matches
    if (
        !req.session.loginOtp ||
        !req.session.loginOtpExpires ||
        req.session.loginPhone !== phone ||
        req.session.loginOtp !== otp
    ) {
        return res.status(400).json({ error: "Invalid or incorrect OTP." });
    }

    // Check if OTP is expired
    if (Date.now() > req.session.loginOtpExpires) {
        // Clear LOGIN session
        req.session.loginOtp = null;
        req.session.loginOtpExpires = null;
        req.session.loginPhone = null;
        return res.status(400).json({ error: "OTP has expired. Please try again." });
    }

    // OTP is correct and valid!
    // Find the user
    try {
        const phoneDigits = phone.replace('+91', '');
        const user = await User.findOne({ phone: phoneDigits });

        if (!user) {
            // Should not happen if send-otp worked, but check anyway
            return res.status(404).json({ error: "User not found." });
        }

        // Clear LOGIN OTP from session
        req.session.loginOtp = null;
        req.session.loginOtpExpires = null;
        req.session.loginPhone = null;

        // --- Manually log the user in ---
        req.login(user, (err) => {
            if (err) {
                console.error("Error logging in user after OTP:", err);
                return res.status(500).json({ error: "Login failed." });
            }
            // Send success response
            res.status(200).json({ success: true, message: "Login successful." });
        });

    } catch (err) {
        console.error("Error finding user during OTP verification:", err);
        res.status(500).json({ error: "An error occurred." });
    }
});


// --- PROTECTED ROUTES ---

// People & Profile Routes
app.get("/people", isLoggedIn, async(req, res) => {
    try {
        // Don't show your own profile in the 'people' list
        const people = await UserProfile.find({ email: { $ne: req.user.email } });
        res.render("people", { people, query: req.query });
    } catch (err) {
        console.error("Error fetching people:", err);
        res.status(500).send("Error loading people list.");
    }
});

app.get("/people/:id", isLoggedIn, async (req, res) => {
    try {
        const person = await UserProfile.findById(req.params.id).lean(); // Use lean
        if (!person) return res.status(404).send("Person not found");
        res.render("profiledetail.ejs", { person, user: req.user, userProfile: res.locals.userProfile });
    } catch (err) {
        console.error("Error fetching person details:", err);
        res.status(500).send("Error loading profile details");
    }
});

// Profile Routes
app.get("/profile", isLoggedIn, (req, res) => {
  try {
      const userProfile = res.locals.userProfile;
      if (userProfile) {
          res.render("profile.ejs", { user: req.user, userProfile: userProfile });
      } else {
          res.redirect("/profile/edit");
      }
  } catch (err) {
      console.error("Error at /profile route:", err);
      res.status(500).send("An error occurred viewing profile.");
  }
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

app.post("/profile", isLoggedIn, async (req, res) => {
  try {
      const profileData = {
          first_name: req.body.first_name,
          last_name: req.body.last_name,
          age: req.body.age || null,
          gender: req.body.gender,
          address: req.body.address,
          work: req.body.work,
          Education: req.body.Education,
          image: req.body.image,
          email: req.user.email, // This links the profile
          isSubscribed: req.body.isSubscribed === 'on' || res.locals.userProfile?.isSubscribed || false,

          // Add phone if it's being updated here
          phone: req.body.phone // Expecting 10 digits
      };

      // We also need to update the base User model's phone
      if (req.body.phone) {
          await User.findOneAndUpdate(
              { email: req.user.email }, // Find by email
              { phone: req.body.phone } // Update phone
          );
      }

      await UserProfile.findOneAndUpdate(
          { email: req.user.email },
          profileData,
          { new: true, upsert: true, setDefaultsOnInsert: true }
      );
      res.redirect("/profile");

  } catch (err) {
      console.error("Error saving profile:", err);
       if (err.code === 11000 && err.keyPattern.phone) {
           // Provide feedback to the user on the edit page
           // This requires rendering the edit page again with an error
           const userProfile = await UserProfile.findOne({ email: req.user.email }).lean();
           return res.render("edit_profile.ejs", {
               user: req.user,
               userProfile: userProfile,
               error: "That phone number is already in use by another account."
           });
       }
      res.status(500).send("An error occurred while saving the profile.");
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






