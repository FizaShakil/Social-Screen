import dotenv from "dotenv";
dotenv.config({
    path: './.env'
})
import { v2 as cloudinary } from 'cloudinary';
import fs from 'fs'

    cloudinary.config({ 
        cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
        api_key: process.env.CLOUDINARY_API_KEY,
        api_secret: process.env.CLOUDINARY_API_SECRET 
    });

    const uploadOnCloudinary = async(localFilePath)=> {
        try {
            if(!localFilePath) {
                return null
            }

            const response = await cloudinary.uploader.upload(
                localFilePath,{
                    resource_type: "auto"
                }
            )
            //file has been uploaded
            console.log("File has been uploaded successfully on cloudinary", response.url)
            fs.unlinkSync(localFilePath)
            return response

        } catch (error) {
            fs.unlinkSync(localFilePath) //remove locally saved temporary file as the operation got failed
            console.error("Failed to upload on Cloudinary",error)
            return null;
        }
    }
export default uploadOnCloudinary