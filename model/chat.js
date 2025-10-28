// ./model/chat.js
import mongoose from 'mongoose';
const { Schema } = mongoose;

const chatSchema = new Schema({
    message: {
        type: String,
        required: true
    },
    senderId: {
        type: Schema.Types.ObjectId,
        ref: 'User', // Or 'UserProfile', depending on your structure
        required: true
    },
    receiverId: {
        type: Schema.Types.ObjectId,
        ref: 'User', // Or 'UserProfile'
        required: true
    }
}, {
    timestamps: true // Automatically adds createdAt and updatedAt
});

const Chat = mongoose.model('Chat', chatSchema);
export default Chat;