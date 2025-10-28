import mongoose from "mongoose";

const userProfileSchema = new mongoose.Schema({
    // The old 'id' field has been completely removed.
    
    username:{
        type:String,
    },
    first_name:{
        type: String,
        default: ""
    },
    last_name: {
        type: String,
        default: ""
    },
    email: {
        type: String,
        default: "",
        unique: true // It's good practice to ensure email is unique here too
    },
    gender:{
        type: String,
    },
    Education: {
        type: String,
        default: ""
    },
    age: {
        type: Number,
        default: null
    },
    address: {
        type: String,
        default: ""
    },
    work: {
        type: String, // Changed to String to match your form
        default: ""
    },
    image: {
        type: String,
        default: ""
    },
    phone:{
        type: String,
        default: "" 
    }
});

const UserProfile = mongoose.model('UserProfilefake', userProfileSchema);

export default UserProfile;