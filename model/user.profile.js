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
subscriptionExpiresAt: Date,
// ✅ VERIFICATION FIELDS
isVerified: {
  type: Boolean,
  default: false
},

govtIdImages: {
  type: [String],
  validate: [
    arr => arr.length <= 6,
    "Maximum 6 government ID files allowed"
  ],
  default: []
},

verificationRequestedAt: Date,
verifiedAt: Date,
verifiedByAdmin: {
  type: mongoose.Schema.Types.ObjectId,
  ref: "User",
  default: null
},
callTokens: {
  type: Number,
  default: 0
},
totalCallMinutes: {
  type: Number,
  default: 0
},
// ✅ MATCHMAKING DETAILS
matchmaking: {
  maritalStatus: {
    type: String,
    enum: ["Single", "Divorced", "Widowed", "Separated"],
    default: ""
  },

  birth: {
    date: Date,
    time: String,
    place: String
  },

  educationDetails: String,
  occupationDetails: String,

  religion: String,
  caste: String,
  subCaste: String,
  gotra: String,

  citizenship: String,
  liveInCity: String,
  liveInState: String,

  height: {
    feet: Number,
    inches: Number
  },

  weight: Number,

  eatingHabit: {
    type: String,
    enum: ["Veg", "Non-Veg", "Eggetarian"],
    default: ""
  },

  smokingHabit: {
    type: String,
    enum: ["No", "Occasionally", "Yes"],
    default: "No"
  },

  drinkingHabit: {
    type: String,
    enum: ["No", "Occasionally", "Yes"],
    default: "No"
  },

  fatherOccupation: String,
  motherOccupation: String,

  brothers: Number,
  sisters: Number,

  familyAnnualIncome: String,

  otherInfo: String
}





}, { timestamps: true });

const UserProfile = mongoose.model('UserProfilefake', userProfileSchema);

export default UserProfile;