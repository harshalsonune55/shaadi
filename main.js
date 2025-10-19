import express from 'express';
const app = express();
import { createServer } from 'http';
import { Server } from 'socket.io';
import { configDotenv } from 'dotenv';
configDotenv();
const PORT = process.env.PORT || 3000;
import ejsmate from 'ejs-mate';
import mongoose from 'mongoose';
import session from "express-session";
import passport from 'passport';
import LocalStrategy from 'passport-local';

// Models
import User from './model/user.js';
import UserProfile from './model/user.profile.js';
import Chat from './model/chat.js';

// Middleware
import { isLoggedIn } from './middleware/auth.js'; 

// Other imports
import Razorpay from "razorpay";
import crypto from "crypto";

const server = createServer(app);
const io = new Server(server);

// --- DATABASE CONNECTION ---
mongoose.connect(process.env.MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log("Connected to MongoDB"))
  .catch(err => console.error("Error connecting to MongoDB:", err));

// --- APP CONFIGURATION ---
app.engine('ejs', ejsmate);
app.set('view engine', 'ejs');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// --- SESSION AND AUTHENTICATION SETUP ---
const sessionConfig = {
    secret: process.env.SESSION_SECRET || "thisisnotagoodsecret",
    resave: false,
    saveUninitialized: true,
    cookie: {
        httpOnly: true,
        // secure: true, // Enable this in production with HTTPS
        expires: Date.now() + 1000 * 60 * 60 * 24 * 7,
        maxAge: 1000 * 60 * 60 * 24 * 7
    }
};

app.use(session(sessionConfig));

app.use(passport.initialize());
app.use(passport.session());

// Configure Passport to use the LocalStrategy with 'email' as the username field
passport.use(new LocalStrategy({ usernameField: 'email' }, User.authenticate()));

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

// Middleware to make user info available in all templates
app.use(async (req, res, next) => {
  res.locals.user = req.user || null;
  
  // If a user is logged in, find their detailed profile
  if (req.user) {
      // We find the profile by matching the email from the authenticated user
      res.locals.userProfile = await UserProfile.findOne({ email: req.user.email });
  } else {
      res.locals.userProfile = null;
  }
  next();
});

// --- SOCKET.IO ---
io.on('connection', (socket) => {
  console.log('A user connected:', socket.id);

  // User joins a specific chat room (for sending/receiving in chat room)
  socket.on('join room', (room) => {
    socket.join(room);
    console.log(`User ${socket.id} joined chat room: ${room}`);
  });

  // User joins their own personal room (for inbox updates)
  socket.on('join user room', (userId) => {
    if (userId) {
       socket.join(userId.toString());
       console.log(`User ${socket.id} joined personal room: ${userId}`);
    }
  });

  // This listener is not strictly needed if the POST route handles everything,
  // but it's good to keep for potential future features.
  socket.on('chat message', (data) => {
    // console.log("Broadcasting message to room:", data.room);
    // socket.to(data.room).emit('chat message', data);
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

// --- ROUTES ---

// Home Route
app.get('/', (req, res) => {
    res.render('home.ejs');
});

// Signup Routes
app.get("/signup", (req, res) => {
    res.render("signup.ejs");
});

app.post("/signup_user", async (req, res, next) => {
  try {
      const { fullname, email, password, confirm_password } = req.body;
      if (password !== confirm_password) {
          return res.render("signup", { error: "Passwords do not match" });
      }
      const user = new User({ email, fullname });
      const registeredUser = await User.register(user, password);
      req.login(registeredUser, err => {
          if (err) return next(err);
          res.redirect("/");
      });
  } catch (e) {
      console.error("Error during signup:", e.message);
      res.render("signup", { error: e.message });
  }
});

// Login Routes
app.get("/login", (req, res) => {
    res.render("login.ejs");
});

// Use passport.authenticate() middleware for login
app.post("/login_user", passport.authenticate("local", {
  failureRedirect: "/login",
}), (req, res) => {
  const redirectUrl = req.session.returnTo || '/';
  delete req.session.returnTo;
  res.redirect(redirectUrl);
});

// Logout Route
app.get("/logout", (req, res, next) => {
    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect('/');
    });
});

// People & Profile Routes
app.get("/people", isLoggedIn, async(req, res) => {
    const people = await UserProfile.find({});
    res.render("people", { people, query: req.query });
});

app.get("/people/:id", isLoggedIn, async (req, res) => {
    const person = await UserProfile.findById(req.params.id);
    if (!person) return res.status(404).send("Person not found");
    res.render("profiledetail.ejs", { person, user: req.user });
});

app.get("/profile", isLoggedIn, async (req, res) => {
  try {
      const userProfile = await UserProfile.findOne({ email: req.user.email });

      if (userProfile) {
          // If profile exists, show it
          res.render("profile.ejs", { user: req.user, userProfile: userProfile });
      } else {
          // If no profile, redirect to the create/edit form
          res.redirect("/profile/edit");
      }
  } catch (err) {
      console.error("Error at /profile route:", err);
      res.status(500).send("An error occurred.");
  }
});

// RENDER EDIT/CREATE FORM
app.get("/profile/edit", isLoggedIn, async (req, res) => {
  try {
      const userProfile = await UserProfile.findOne({ email: req.user.email });
      // Render the form, passing existing profile data (or null if it's a new user)
      res.render("edit_profile.ejs", { user: req.user, userProfile: userProfile });
  } catch (err) {
      console.error("Error rendering edit profile page:", err);
      res.status(500).send("An error occurred.");
  }
});

// HANDLE FORM SUBMISSION (CREATE or UPDATE)
app.post("/profile", isLoggedIn, async (req, res) => {
  try {
      const profileData = {
          first_name: req.body.first_name,
          last_name: req.body.last_name,
          age: req.body.age,
          gender: req.body.gender,
          address: req.body.address,
          work: req.body.work,
          Education: req.body.Education,
          image: req.body.image,
          email: req.user.email, // Always link to the logged-in user's email
          username: req.user.username
      };

      // Find profile by email and update it, OR create it if it doesn't exist (upsert: true)
      await UserProfile.findOneAndUpdate(
          { email: req.user.email },
          profileData,
          { new: true, upsert: true, setDefaultsOnInsert: true }
      );

      res.redirect("/profile"); // Redirect back to the view profile page
  } catch (err) {
      console.error("Error saving profile:", err);
      res.status(500).send("An error occurred while saving the profile.");
  }
});

// INBOX ROUTE
app.get("/inbox", isLoggedIn, async (req, res) => {
  try {
      const userId = req.user._id;

      // 1. Find all messages involving the current user
      const messages = await Chat.find({
          $or: [{ senderId: userId }, { receiverId: userId }]
      }).sort({ createdAt: -1 });

      // 2. Group messages by conversation partner
      const conversationsMap = new Map();
      messages.forEach(msg => {
          // Determine the "other person" in the chat
          const otherUserId = msg.senderId.toString() === userId.toString() ? msg.receiverId.toString() : msg.senderId.toString();
          
          // If we haven't seen this conversation yet, add it with the latest message
          if (!conversationsMap.has(otherUserId)) {
              conversationsMap.set(otherUserId, msg);
          }
      });

      // 3. Fetch profile details and format the data for the template
      const conversations = [];
      for (const [otherUserId, lastMessage] of conversationsMap.entries()) {
          const participantProfile = await UserProfile.findById(otherUserId);
          if (participantProfile) {
              conversations.push({
                  participant: participantProfile,
                  lastMessage: lastMessage
              });
          }
      }
      
      // Sort conversations to show the most recent ones first
      conversations.sort((a, b) => b.lastMessage.createdAt - a.lastMessage.createdAt);

      res.render("inbox", { conversations });
  } catch (err) {
      console.error("Error fetching inbox:", err);
      res.status(500).send("Error loading your inbox.");
  }
});

// CHAT ROOM ROUTE (Renders the page)
app.get("/chat/:personId", isLoggedIn, async (req, res) => {
    try {
        const { personId } = req.params;
        const person = await UserProfile.findById(personId);
        if (!person) return res.status(404).send("Person not found");
        res.render("chat_room.ejs", { person, currentUser: req.user });
    } catch (error) {
        console.error("Error loading chat room:", error);
        res.status(500).send("Error loading chat room");
    }
});

// CHAT HISTORY API ROUTE (Fetches message data)
app.get("/api/chat/:personId", isLoggedIn, async (req, res) => {
    try { 
        const userId = req.user?._id;
        const personId = req.params.personId; 

        console.log("--- Fetching Chat History ---");
        console.log("Current User ID (userId):", userId, `(Type: ${typeof userId})`);
        console.log("Other Person ID (personId):", personId, `(Type: ${typeof personId})`);

        if (!userId || !personId) {
            console.error("Missing userId or personId");
            return res.status(400).json({ error: "Invalid user IDs provided" });
        }

        const userIdString = userId.toString();
        const personIdString = personId.toString();
        console.log("Querying with User ID:", userIdString);
        console.log("Querying with Person ID:", personIdString);
        
        const messages = await Chat.find({
            $or: [
                { senderId: userIdString, receiverId: personIdString },
                { senderId: personIdString, receiverId: userIdString },
            ]
        }).sort({ createdAt: 1 });

        console.log(`Found ${messages.length} messages between ${userIdString} and ${personIdString}`); 

        res.json(messages);

    } catch (error) { 
        console.error("Error in /api/chat/:personId:", error);
        res.status(500).json({ error: "Failed to fetch chat history due to server error" });
    }
});

// SEND MESSAGE ROUTE (Handles saving and emitting)
// This is the correct, complex route you intended to use.
app.post("/chat/send", isLoggedIn, async (req, res) => {
  const { receiverId, message } = req.body;
  const senderId = req.user?._id;

  if (!senderId || !receiverId || !message) {
      console.error("Missing senderId, receiverId, or message in /chat/send");
      return res.status(400).json({ error: "Missing required fields" });
  }

  try {
      // Save the message
      const chatMsg = new Chat({ senderId, receiverId, message });
      await chatMsg.save();
      console.log("Message saved:", chatMsg._id);

      // --- Function to get participant data (handles missing profiles) ---
      async function getParticipantData(userId) {
          const userProfile = await UserProfile.findById(userId).lean(); // Use .lean() for plain JS object
          if (userProfile) {
              return {
                  _id: userProfile._id,
                  first_name: userProfile.first_name || 'User',
                  last_name: userProfile.last_name || '',
                  image: userProfile.image || `https://ui-avatars.com/api/?name=${userProfile.first_name || 'U'}`
              };
          }
          // Fallback to basic User data
          const basicUser = await User.findById(userId).lean();
          if (basicUser) {
               console.warn(`UserProfile not found for ID: ${userId}, using basic User data for inbox update.`);
              return {
                  _id: basicUser._id,
                  first_name: basicUser.fullname?.split(' ')[0] || 'User',
                  last_name: basicUser.fullname?.split(' ').slice(1).join(' ') || '',
                  image: `https://ui-avatars.com/api/?name=${basicUser.fullname || 'U'}`
              };
          }
          // Final fallback
          console.error(`Could not find any user data for ID: ${userId} during inbox update emission.`);
          return {
              _id: userId, // Still need the ID
              first_name: 'Unknown',
              last_name: 'User',
              image: 'https://ui-avatars.com/api/?name=?'
          };
      }
      // --- End function ---

      // Get data for both participants
      const senderData = await getParticipantData(senderId);
      const receiverData = await getParticipantData(receiverId);

      // Prepare data structure for the event (matches structure from /inbox route)
      const lastMessageData = {
           message: chatMsg.message,
           createdAt: chatMsg.createdAt // Ensure timestamp is included
      };

      const updateDataForReceiver = {
          participant: senderData,       // Receiver sees the sender as participant
          lastMessage: lastMessageData
      };
      const updateDataForSender = {
          participant: receiverData,      // Sender sees the receiver as participant
          lastMessage: lastMessageData
      };

      // Emit 'update inbox' event
      io.to(receiverId.toString()).emit('update inbox', updateDataForReceiver);
      console.log(`Emitted 'update inbox' to room ${receiverId.toString()} with data:`, JSON.stringify(updateDataForReceiver));

      io.to(senderId.toString()).emit('update inbox', updateDataForSender);
      console.log(`Emitted 'update inbox' to room ${senderId.toString()} with data:`, JSON.stringify(updateDataForSender));

     // Also emit the message to the specific chat room for live chat updates
     const roomId = [senderId.toString(), receiverId.toString()].sort().join('-');
      io.to(roomId).emit('chat message', {
          room: roomId,
          message: chatMsg.message,
          senderId: chatMsg.senderId.toString(), // Ensure IDs are strings here too
          createdAt: chatMsg.createdAt
      });
      console.log(`Emitted 'chat message' to room ${roomId}`);

      // Respond to the POST request
      res.status(200).json({ success: true, message: "Message saved and emitted." });

  } catch (error) {
       console.error("Error sending chat message:", error);
       res.status(500).json({ success: false, message: "Failed to send message." });
  }
});

// *** THE DUPLICATE ROUTE WAS HERE AND HAS BEEN DELETED ***

// Pricing and Payment Routes
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
      const order = await razorpay.orders.create({
        amount: amount * 100, 
        currency: "INR",
        payment_capture: 1,
      });
  
      res.json({ orderId: order.id });
    } catch (err) {
      console.error(err);
      res.status(500).send("Error creating order");
    }
});

app.post("/verify-payment", isLoggedIn, (req, res) => {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
  
    const hmac = crypto.createHmac("sha256", process.env.Razor_key_secret);
    hmac.update(razorpay_order_id + "|" + razorpay_payment_id);
    const generated_signature = hmac.digest("hex");
  
    if (generated_signature === razorpay_signature) {
      console.log("Payment verified:", razorpay_payment_id);
      res.json({ success: true });
    } else {
      res.status(400).json({ success: false, message: "Invalid signature" });
    }
});


// --- SERVER LISTEN ---
server.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});