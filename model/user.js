import mongoose from 'mongoose';
const { Schema } = mongoose;
import passportLocalMongoose from 'passport-local-mongoose';

const userSchema = new Schema({
    // email is already added by passport-local-mongoose
    fullname: String,
    googleId: String,
    
    // --- ADD THIS ---
    phone: {
        type: String,
        unique: true, // No two users can have the same number
        sparse: true, // Allows multiple 'null' values (for Google users)
        validate: {
            validator: function(v) {
                // Simple regex for a 10-digit number.
                return /^\d{10}$/.test(v);
            },
            message: props => `${props.value} is not a valid 10-digit phone number!`
        }
    }
    // ... any other fields you have
});

// 'usernameField: "email"' is already set in your main.js
userSchema.plugin(passportLocalMongoose, { usernameField: 'email' });

const User = mongoose.model('User', userSchema);
export default User;

