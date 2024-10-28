import { Router } from "express";
import {upload} from '../middlewares/multer.middleware.js'
import { registerUser, loginUser, logoutUser, accessRefreshToken } from "../controllers/user.controller.js";
import {verifyJWT}  from "../middlewares/auth.middleware.js";
const userRouter = Router()

userRouter.route('/register').post(
    upload.fields([
        {
            name: "avatar",
            maxCount: 1
        },
        {
            name: "coverImage",
            maxCount: 1
        }
    ]),
    
    registerUser
)
userRouter.route('./login').post(loginUser)
userRouter.route('./logout').post(verifyJWT, logoutUser)
userRouter.route("./refresh-token").post(accessRefreshToken)

export default userRouter