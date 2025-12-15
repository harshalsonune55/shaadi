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

    image: { type: String, default: "" },       
    coverImage: { type: String, default: "" },  

    
    about: { type: String },
expertise: [{ type: String }],
interests: [{ type: String }],


});

const UserProfile = mongoose.model('UserProfilefake', userProfileSchema);

export default UserProfile;