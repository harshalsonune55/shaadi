import mongoose from "mongoose";

const userProfileSchema = new mongoose.Schema({
    username: String,

    first_name: { type: String, default: "" },
    last_name: { type: String, default: "" },

    phone: {
        type: String,
        required: true,
        unique: true
      },

    gender: String,
    Education: String,
    age: Number,
    address: String,
    work: String,
    photos: [{ type: String }],   

    image: { type: String, default: "" },       
    coverImage: { type: String, default: "" },  

    
    about: { type: String },
expertise: [{ type: String }],
interests: [{ type: String }],
likes: [
  {
    type: mongoose.Schema.Types.ObjectId,
    ref: "UserProfile"
  }
],
// ✅ SUBSCRIPTION FIELDS
isSubscribed: {
  type: Boolean,
  default: false
},

subscriptionPlan: {
  type: String,
  enum: ["Basic", "Premium", "Elite"],
  default: null
},

subscriptionStartedAt: Date,
subscriptionExpiresAt: Date



}, { timestamps: true });

const UserProfile = mongoose.model('UserProfilefake', userProfileSchema);

export default UserProfile;