import express from 'express';
const app = express();
import { configDotenv } from 'dotenv';
configDotenv();
const PORT = process.env.PORT || 3000;
import ejsmate from 'ejs-mate';
import mongoose from 'mongoose';
import User from './model/user.js';
import { v4 as uuidv4 } from 'uuid';
import { setUser,getUser } from './service/auth.js';
import cookieParser from 'cookie-parser';
import session from "express-session";
import UserProfile from './model/user.profile.js';
import Razorpay from "razorpay";
import crypto from "crypto";
import chat from './model/chat.js';
app.use(cookieParser());
// import { restricttologinuser } from './middleware/auth.js';

mongoose.connect(process.env.MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log("Connected to MongoDB");
}).catch(err => {
    console.error("Error connecting to MongoDB:", err);
}); 



app.use(session({
    secret: "your-secret-key",   // change to a secure random string
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }    // set secure: true if using https
  }));

app.engine('ejs', ejsmate);
app.use(express.json());   
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use((req, res, next) => {
    res.locals.user = req.session.user || null;
    next();
  });
  const razorpay = new Razorpay({
    key_id: process.env.Razor_key_id,
    key_secret: process.env.Razor_key_secret,
  });


app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

app.post("/login_user",(req,res)=>{
    const {email,password} = req.body;
    User.find({ email, password }).then(user=>{
        if(user){
            
            const sessionId = uuidv4();
            setUser(sessionId, user._id);
            req.session.user = user;
            res.cookie("sessionId", sessionId, { httpOnly: true });
            return res.redirect("/");

        } else {
            return res.render("login", { error: "Passwords do not match" });
        }
    }).catch(err=>{
        console.error("Error during login:", err);
        return res.render("login", { error: "Error during login. Please try again." });
    });

});

app.post("/create-order", async (req, res) => {
    try {
      const { amount } = req.body; // amount in INR
  
      const order = await razorpay.orders.create({
        amount: amount * 100, // Razorpay expects paise
        currency: "INR",
        payment_capture: 1,
      });
  
      res.json({ orderId: order.id });
    } catch (err) {
      console.error(err);
      res.status(500).send("Error creating order");
    }
  });

app.post("/signup_user",(req,res)=>{
    const {fullname,email,password,username,confirm_password} = req.body;
    if(password !== confirm_password){
        return res.render("signup", { error: "Passwords do not match" });
    }
    console.log(req.body);
    const newUser = new User({
        username,
        email,
        password,
        fullname
    });
    newUser.save().then(()=>{
        res.redirect("/");
    }).catch(err=>{
        console.error("Error saving user:", err);
        res.render("signup", { error: "Error creating account. Please try again." });
    });
});


app.get("/login",(req,res)=>{
    res.render("login.ejs");
});


app.get("/people", async(req, res) => {
    try {
        const { name, address, minAge, maxAge, gender, interest } = req.query;
    
        let filter = {};
    
        // Name filter
        if (name) {
          filter.$or = [
            { first_name: new RegExp(name, "i") },
            { last_name: new RegExp(name, "i") }
          ];
        }
    
        // Address filter
        if (address) {
          filter.address = new RegExp(address, "i");
        }
    
        // Age filter
        if (minAge || maxAge) {
          filter.age = {};
          if (minAge) filter.age.$gte = Number(minAge);
          if (maxAge) filter.age.$lte = Number(maxAge);
        }
    
        // Gender filter
        if (gender) {
          filter.gender = gender;
        }
    
        // Interests filter (assuming array of interests in DB)
        if (interest) {
          filter.interests = { $in: [new RegExp(interest, "i")] };
        }
    
        const people = await UserProfile.find(filter);
        res.render("people", { people, query: req.query });
      } catch (err) {
        console.error("Error fetching people:", err);
        res.status(500).send("Internal Server Error");
      }
  });
  

app.get("/signup",(req,res)=>{
    res.render("signup.ejs");
});

app.get("/people/:id", async (req, res) => {
    try {
      const person = await UserProfile.findById(req.params.id);
      if (!person) return res.status(404).send("Person not found");
      res.render("profiledetail.ejs", { person, user: req.session.user });
    } catch (err) {
      console.error("Error fetching person:", err);
      res.status(500).send("Internal Server Error");
    }
  });
  


app.get('/', (req, res) => {
    res.render("home.ejs");
});

app.get("/chat/:personId", async (req, res) => {
    const userId = req.session.user?._id;
    const { personId } = req.params;
  
    const messages = await Chat.find({
      $or: [
        { senderId: userId, receiverId: personId },
        { senderId: personId, receiverId: userId },
      ]
    }).sort({ createdAt: 1 });
  
    res.json(messages);
  });


  app.post("/chat/send", async (req, res) => {
    const { receiverId, message } = req.body;
    const senderId = req.session.user?._id;
    if (!senderId) return res.status(401).json({ error: "Not logged in" });
  
    const chatMsg = new Chat({ senderId, receiverId, message });
    await chatMsg.save();
    res.json(chatMsg);
  });

app.post("/verify-payment", (req, res) => {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
  
    const hmac = crypto.createHmac("sha256", process.env.Razor_key_secret);
    hmac.update(razorpay_order_id + "|" + razorpay_payment_id);
    const generated_signature = hmac.digest("hex");
  
    if (generated_signature === razorpay_signature) {
      // ✅ Payment verified
      console.log("Payment verified:", razorpay_payment_id);
      res.json({ success: true });
    } else {
      // ❌ Payment failed
      res.status(400).json({ success: false, message: "Invalid signature" });
    }
  });


 

  //video calling function

//   import { google } from 'googleapis';

// const auth = new google.auth.GoogleAuth({
//   keyFile: "path-to-service-account.json",
//   scopes: ["https://www.googleapis.com/auth/calendar"]
// });

// const calendar = google.calendar({ version: "v3", auth });

// async function createMeet() {
//   const event = {
//     summary: "Chat with Candidate",
//     start: { dateTime: new Date().toISOString() },
//     end: { dateTime: new Date(Date.now() + 30 * 60 * 1000).toISOString() }, // 30 min
//     conferenceData: { createRequest: { requestId: `${Date.now()}` } }
//   };

//   const response = await calendar.events.insert({
//     calendarId: "primary",
//     requestBody: event,
//     conferenceDataVersion: 1
//   });

//   return response.data.hangoutLink; // Google Meet link
// }