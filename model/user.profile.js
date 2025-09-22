import mongoose from "mongoose";

const userProfileSchema = new mongoose.Schema({
    id:{
        type: Number, unique: true  
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
        default: "" 
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
        type: [String],
        default: []
    },
    image: {
        type: String,
        default: ""
    }
});

const UserProfile = mongoose.model('UserProfilefake', userProfileSchema);

export default UserProfile;