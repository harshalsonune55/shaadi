import mongoose from "mongoose";

const adminUserProfileSchema = new mongoose.Schema({
  createdByAdmin: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true
  },

  // BASIC
  first_name: String,
  last_name: String,
  phone: String,
  gender: String,
  age: Number,
  address: String,
  work: String,
  Education: String,

  // ABOUT
  about: String,
  expertise: [String],
  interests: [String],

  // STATUS
  isSubscribed: Boolean,
  subscriptionPlan: String,
  isVerified: Boolean,

  // MEDIA
  photos: [String],
  image: String,
  coverImage: String,

  // MATCHMAKING
  matchmaking: {
    maritalStatus: String,

    birth: {
      date: Date,
      time: String,
      place: String
    },

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

    eatingHabit: String,
    smokingHabit: String,
    drinkingHabit: String,

    fatherOccupation: String,
    motherOccupation: String,

    brothers: Number,
    sisters: Number,

    familyAnnualIncome: String,
    otherInfo: String
  }

}, { timestamps: true });

const AdminUserProfile = mongoose.model("AdminUserProfile", adminUserProfileSchema);
export default AdminUserProfile;
