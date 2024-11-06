import {asyncHandler} from '../utils/asyncHandler.js'
import {ApiError} from '../utils/ApiError.js'
import { User } from '../models/user.model.js';
import uploadOnCloudinary from '../utils/cloudinary.js';
import {ApiResponse} from '../utils/ApiResponse.js'
import jwt from 'jsonwebtoken'

const generateAccessAndRefreshToken = async(userId)=> {
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessTokens()
        const refreshToken = user.generateRefreshTokens()

        user.refreshToken = refreshToken
        await user.save({
            validateBeforeSave: false
        })
        return {accessToken, refreshToken}

    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating access and refresh token")
    }
}

const registerUser = asyncHandler(async (req,res)=>{
    // res.status(200).json({
    //     message: "OK"
    // })

    // get user details from frontend
    // console.log("files are: ", req.files);
    // console.log("body is:", req.body); 


    const{ fullName, email, username, password} = req.body;
    console.log("Email" , email)

    //validation check-not any field is empty
    if([fullName, email, password, username].some((field)=>field?.trim === " ")){
        throw new ApiError(400, "All fields are required")
    }

    //user already exists or not
    const existedUser = await User.findOne(
        {
            $or: [{username}, {email}]
        }
    )
    if(existedUser){
        throw new ApiError(409, "User with the username or email already exists ")
    } // if user exists , throw error

    // check for images-avatar
    // const avatarLocalPath = req.files?.avatar[0]?.path
    // const coverImageLocalPath = req.files?.coverImage[0]?.path

    const avatarLocalPath = req.files?.avatar?.[0]?.path;
    // const coverImageLocalPath = req.files?.coverImage?.[0]?.path;

    let coverImageLocalPath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
        coverImageLocalPath = req.files.coverImage[0].path
    }

    // console.log("avatar local path is:", req.files?.avatar[0]?.path)

    // avatar is compulsory

    if(!avatarLocalPath){
        throw new ApiError(400, "Avatar file required")
    }
    
    // upload files and avatar image on cloudinary

    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await  uploadOnCloudinary(coverImageLocalPath)


    // check avatar is uploaded correctly or not on cloudinary
    if(!avatar){
        throw new ApiError (400, "Failed to upload avatar")
    }
    // if everything is working fine, create entry in DB

        const user = await User.create({
            fullName,
            avatar: avatar.url,
            coverImage: coverImage?.url || " ",
            password,
            email,
            username: username.toLowerCase()
        })

        // check if user created or not, if created then remove password & refresh token from response
        const createdUser = await User.findById(
            user._id).select(
                "-password -refreshToken"
            )

            //user comes or not, check it
            if(!createdUser){
                throw new ApiError(500, "Something went wrong while registering the user")
            }

            //return response

            return res.status(201).json(
                new ApiResponse(200, createdUser, "User registered successfully!!")
            )
})

const loginUser = asyncHandler(async(req,res)=>{
    // req-body data
    const {username, email, password} = req.body

    if(!username && !email){
        throw new ApiError(400, "Username or email is required")
    }
     
    // find user in database
    const user = await User.findOne({
        $or: [{username},{email}]
    })

    if(!user){
        throw new ApiError(404, "User not Found")
    }

    //check password
    const isPasswordValid = await user.isPasswordCorrect(password)
    if(!isPasswordValid){
        throw new ApiError(401, "Invalid user credentials")
    }

    //generate access and refresh token
    const {accessToken, refreshToken} = await generateAccessAndRefreshToken(user._id)

    const loggedInUser = await User.findById(user._id)
    .select("-password -refreshToken")

    const options = { // it is used to make sure that the cookies are modified only from server
        httpOnly: true,
        secure: true 
    }

    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new ApiResponse(
            200, {
                user: loggedInUser, accessToken, refreshToken
            },
            "User logged in Successfully !! "
        )
    )
})

const logoutUser = asyncHandler(async(req,res)=>{
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: undefined
            }
        },
        {
            new: true
        }
    )
    const options = {
        httpOnly: true,
        secure: true
    }

    return res.
    status(200)
    .clearCookie("accessToken",options)
    .clearCookie("refreshToken", options)
    .json(
        new ApiResponse(200, {}, "User Logged Out successfully !!")
    )
})

const accessRefreshToken = asyncHandler(async(req,res)=>{
    const incomingRefreshToken = req.cookies.refreshToken || req.cookies.refreshToken
    try {
        if(!incomingRefreshToken){ // incoming token is not valid
            throw new ApiError(401, "Unauthorized request")
        }
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        ) // decoding the incoming refresh token, only the person who has refresh token secret can verify it
        
        const user = await User.findById(decodedToken?._id)
        if(!user){
            throw new ApiError(401, "Invalid refresh Token")
        }
        if(incomingRefreshToken !== user?.refreshToken){
            throw new ApiError(401, "Refresh Token is expired or used")
        }
        const options = {
            httpOnly: true,
            secure: true
        }
        const {accessToken, newRefreshToken} = generateAccessAndRefreshToken(user._id)
        return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", newRefreshToken, options)
        .json(
            new ApiResponse(
                200,
                {accessToken, refreshToken: newRefreshToken},
                "Access Token Refreshed"
            )
        )
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid Refresh Token")
    }
})

const changeCurrentPassword = asyncHandler(async(req,res)=>{
    const {oldPassword, newPassword} = req.body

    const user = await User.findById(req.user?._id)

    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

    if(!isPasswordCorrect){
        throw new ApiError(400, "Invalid old password")
    }

    user.password = newPassword

    await user.save({
        validateBeforeSave: false
    })

    return res
    .status(200)
    .json(
        new ApiResponse(200, {}, "Password changed successfully!")
    )
})

const getCurrentUser = asyncHandler(async(req,res)=>{
    return res
    .status(200)
    .json(
        new ApiResponse(200, req.user,"Current user fetched successfully!")
    )
})

const updateAccountDetails = asyncHandler(async(req,res)=>{
    const {fullName, email} = req.body

    if(!(fullName || email)){
        throw new ApiError(400, "All fields are required")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                fullName,
                email
            }
        },
        {new: true}
    ).select("-password")

    return res
    .status(200)
    .json(
        new ApiResponse(200, user, "User account details updated successfully!")
    )
})

const updateUserAvatar = asyncHandler(async(req,res)=>{
    const avatarLocalPath = req.files?.path
    if(!avatarLocalPath){
        throw new ApiError(400, "Avatar File is required for updating")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)

    if(!avatar.url){
        throw new ApiError(400, "Error while uploading avatar file on cloudinary")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                avatar: avatar.url
            }
        },
        {new: true}
    )
    
    return res
    .status(200)
    .json(
        new ApiResponse(200, user, "Avatar Updated Successfully!")
    )
})
const updateUserCoverImage = asyncHandler(async(req,res)=>{
    const coverImageLocalPath = req.files?.path
    if(!coverImageLocalPath){
        throw new ApiError(400, "Cover Image File is required for updating")
    }

    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!coverImage.url){
        throw new ApiError(400, "Error while uploading avatar file on cloudinary")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                coverImage: coverImage.url
            }
        },
        {new: true}
    )
    
    return res
    .status(200)
    .json(
        new ApiResponse(200, user, "Cover Image Updated Successfully!")
    )
})
const getUserChannelProfile = asyncHandler(async(req,res)=>{
    const {username} = req.params
 
    if(!username.trim()){
        throw new ApiError(400, "Username is missing")
    }

    const channel = await User.aggregate(
        [
            {
                $match: {
                    username: username?.toLowerCase()
                }
            },
            {
                $lookup:{
                    from: "subscriptions",
                    localField: "_id",
                    foreignField: "channel",
                    as: "subscribers" // how much subscriber a user's channel have
                }
            },
            {
                $lookup:{
                    from: "subscriptions",
                    localField: "_id",
                    foreignField: "subscriber",
                    as: "subscribedTo" // to whom the user has subscribed
                }
            },
            {
                $addFields: {
                    subscribersCount:{
                        $size: "$subscribers"
                    },
                    SubscribedToCount:{
                        $size: "$subscribedTo"
                    },
                    isSubscribed:{
                        $cond:{
                            $if: {
                                $in:[req.user?._id,"$subscribers.subscriber"]
                            },
                            then: true,
                            else: false
                        }
                    }
                }
            },
            {
                $project:{
                    fullName: 1,
                    username: 1,
                    subscribersCount: 1,
                    SubscribedToCount: 1,
                    isSubscribed: 1,
                    avatar: 1,
                    coverImage: 1,
                    email: 1
                }
            }
        ]
    )

    if(!channel?.length()){
        throw new ApiError(400, "Channel doesnot exist")
    }

    res
    .status(200)
    .json(
        new ApiResponse(200, 
            channel[0], 
            "User Channel fetched successfully!!"
        )
    )
})

const getUserWatchHistory = asyncHandler(async(req,res)=>{
    const user = await User.aggregate(
        [
            {
                $match: {
                    _id: new mongoose.Types.ObjectId(req.user._id)
                }
            },
            {
                $lookup:{
                    from: "videos",
                    localField: "watchHistory",
                    foreignField: "_id",
                    as: "watchHistory",
                    pipeline:[
                        {
                            $lookup:{
                                from: "users",
                                localField: "owner",
                                foreignField: "_id",
                                as: "owner",
                                pipeline:[
                                    {
                                        $project:{
                                            fullName: 1,
                                            username: 1,
                                            avatar: 1
                                        }
                                    }
                                ]
                            }
                        },
                        {
                            $addFields:{
                                owner:{
                                    $first: "$owner"
                                }
                            }
                        }
                    ]
                }
            }
        ]
    )

    return res
    .status(200)
    .json(
        new ApiResponse(
            200,
            user[0].watchHistory,
            "Watch history fetched successfully !"
        )
    )
})
export {
    registerUser, 
    loginUser, 
    logoutUser, 
    accessRefreshToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage,
    getUserChannelProfile,
    getUserWatchHistory
}