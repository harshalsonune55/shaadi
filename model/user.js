// model/user.js
import mongoose from "mongoose";
const { Schema } = mongoose;

const userSchema = new Schema(
  {
    fullname: {
      type: String,
      trim: true,
    },

    // 🔑 PRIMARY LOGIN FIELD
    phone: {
      type: String,
      unique: true,
      required: true,
      validate: {
        validator: v => /^\d{10}$/.test(v),
        message: props => `${props.value} is not a valid 10-digit phone number`,
      },
    },

    // Optional email (profile / future use)
    
    isAdmin: {
        type: Boolean,
        default: false
      },
      

    // OTP fields (temporary)
    otp: String,
    otpExpires: Date,
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);
export default User;
