import { Router } from "express";
import {
    changePassword,
    forgotPassword,
    getProfile,
    login,
    logout,
    register,
    resetPassword,
    updateUser,
    googleAuth,
    googleAuthCallback,
    githubAuth,
    githubAuthCallback
} from "../controllers/user.controller.js";
import { isLoggedIn } from "../middleware/auth.middleware.js";
import upload from "../middleware/multer.middleware.js";

const router = Router();

router.post('/register', upload.single('avatar'), register);
router.post('/login', login);
router.get('/logout', logout);
router.get('/me', isLoggedIn, getProfile);

// Password reset routes
router.post('/reset', forgotPassword);
router.post('/reset/:resetToken', resetPassword);
router.post('/change-password', isLoggedIn, changePassword);
router.post('/update/:id', isLoggedIn, upload.single('avatar'), updateUser);

// Google OAuth routes
router.get('/auth/google', googleAuth);
router.get('/auth/google/callback', googleAuthCallback);

// GitHub OAuth routes
router.get('/auth/github', githubAuth);
router.get('/auth/github/callback', githubAuthCallback);

export default router;
