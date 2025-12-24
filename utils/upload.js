// utils/upload.js
import { v2 as cloudinary } from "cloudinary"; // Use v2 specifically
import { CloudinaryStorage } from "multer-storage-cloudinary";
import { configDotenv } from "dotenv";

configDotenv();

// Debug: Check if keys are actually loading (Remove this after testing)
console.log("Cloudinary Config Name:", process.env.CLOUDINARY_CLOUD_NAME);

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

export const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: "shaadiwali_profiles",
    allowed_formats: ["jpg", "png", "jpeg", "webp"], // Note: allowed_formats is correct for newer versions
    transformation: [{ width: 500, height: 500, crop: "limit" }] // Optional: prevents massive uploads
  }
});

export const cloudinaryInstance = cloudinary;