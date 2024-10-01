import User from "../models/user.model.js";
import AppError from "../utils/error.utils.js";
import cloudinary from 'cloudinary'
import fs from 'fs/promises'
import sendEmail from "../utils/sendEmail.js";
import crypto from 'crypto'
import passport from "../utils/passport.js";
const cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // use secure cookies in production
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
};
const register = async (req, res, next) => {
    try {
        const { fullName, email, password } = req.body;
        if (!fullName || !email || !password) {
            return next(new AppError("All fields are required", 400));
        }
        const userExists = await User.findOne({ email });

        if (userExists) {
            return next(new AppError("Email already exists", 400));
        }
        const user = await User.create({
            fullName,
            email,
            password,
            avatar: {
                public_id: email, // This should be updated to actual Cloudinary public ID after uploading the image
                secure_url: 'https://res.cloudinary.com/{cloud_name}/image/upload/{transformation}/{public_id}.{format}' // Update this as needed
            }
        });

        if (!user) {
            return next(new AppError('User registration failed, please try again', 400));
        }
        // Todo: File upload

        if (req.file) {
            console.log(req.file)
            try {
                const result = await cloudinary.v2.uploader.upload(req.file.path, {
                    folder: "lms",
                    width: 250,
                    height: 250,
                    gravity: "faces",
                    crop: "fill",
                });

                if (result) {
                    user.avatar.public_id = result.public_id;
                    user.avatar.secure_url = result.secure_url;

                    // Remove the file from the server
                    fs.rm(`uploads/${req.file.filename}`);
                }
            } catch (e) {
                return next(new AppError(e.message || "File not uploaded please try again", 500));
            }
        }

        user.password = undefined;
        const token = await user.generateJWTToken();
        console.log(token, "hii");
        res.cookie('token', token, cookieOptions);
        res.status(201).json({
            success: true,
            message: 'User Registered Successfully',
            user,
        });
    } catch (error) {
        return next(new AppError(error.message, 500));
    }
};

const login = async (req, res, next) => {
    try {
        console.log(req.body)
        const { email, password } = req.body;
        if (!email || !password) {
            return next(new AppError("All fields are required", 400));
        }
        const user = await User.findOne({ email }).select('+password');

        if (!user || !(await user.comparePassword(password))) { // Ensure password comparison is awaited
            return next(new AppError("Email or password does not match", 400));
        }
        const token = await user.generateJWTToken();
        console.log(token)
        user.password = undefined;
        res.cookie('token', token, cookieOptions);

        res.status(200).json({
            success: true,
            message: 'User Logged in Successfully',
            user,
        });
    } catch (error) {
        return next(new AppError(error.message, 500));
    }
};

const logout = (req, res) => {
    try {
        res.cookie('token', null, {
            secure: process.env.NODE_ENV === 'production', // Ensure cookie is only sent over HTTPS in production
            maxAge: 0,
            httpOnly: true
        });
        res.status(200).json({
            success: true,
            message: 'User logged out successfully'
        });
    } catch (error) {
        return next(new AppError('Failed to log out', 500));
    }
};

const getProfile = async (req, res, next) => {
    try {
        const userId = req.user.id;
        const user = await User.findById(userId);

        if (!user) {
            return next(new AppError('User not found', 404));
        }

        res.status(200).json({
            success: true,
            message: 'User details',
            user
        });
    } catch (error) {
        return next(new AppError('Failed to fetch profile', 500));
    }
};

const forgotPassword = async (req, res, next) => {
    const { email } = req.body;
    // check if user does'nt pass email
    if (!email) {
        return next(new AppError('Email is required', 400))
    }

    const user = await User.findOne({ email });
    // check if user not registered with the email
    if (!user) {
        return next(new AppError('Email not registered', 400))
    }

    const resetToken = await user.generatePasswordResetToken();

    await user.save();

    const resetPasswordURL = `${process.env.CLIENT_URL}/reset/${resetToken}`

    const subject = 'Reset Password';
    const message = `You can reset your password by clicking ${resetPasswordURL} Reset your password</$>\nIf the above link does not work for some reason then copy paste this link in new tab ${resetPasswordURL}.\n If you have not requested this, kindly ignore.`;

    try {
        await sendEmail(email, subject, message);

        res.status(200).json({
            success: true,
            message: `Reset password token has been sent to ${email}`,
        });
    } catch (e) {
        user.forgotPasswordExpiry = undefined;
        user.forgotPasswordToken = undefined;
        await user.save();
        return next(new AppError(e.message, 500));
    }

}
// reset password
const resetPassword = async (req, res, next) => {
    try {
        const { resetToken } = req.params;

        const { password } = req.body;
        console.log(resetToken, password)
        const forgetPasswordToken = crypto
            .createHash('sha256')
            .update(resetToken)
            .digest('hex');
        console.log(forgetPasswordToken)
        const user = await User.findOne({
            forgetPasswordToken,
            forgetPasswordEnquiry: { $gt: Date.now() }
        })

        if (!user) {
            return next(new AppError("Token is invalid or expired, please try again", 400));
        }

        user.password = password;
        user.forgetPasswordToken = undefined;
        user.forgetPasswordEnquiry = undefined;
        console.log(user)
        await user.save();

        res.status(200).json({
            success: true,
            message: "Password changed successfully"
        })
    } catch (e) {
        return next(new AppError(e.message, 500))
    }
}


// change password
const changePassword = async (req, res, next) => {
    try {
        const { oldPassword, newPassword } = req.body;
        const { id } = req.user;

        if (!oldPassword || !newPassword) {
            return next(new AppError("All fields are requared", 400));
        }

        const user = await User.findById(id).select('+password');

        if (!user) {
            return next(new AppError("User does not exist", 400));
        }

        if (!(bcrypt.compareSync(oldPassword, user.password))) {
            return next(new AppError("Invalid Old Password", 400));
        }

        user.password = newPassword;

        await user.save();

        res.status(200).json({
            success: true,
            message: "Password changed successfully"
        })
    } catch (e) {
        return next(new AppError(e.message, 500))
    }

}

const updateUser = async (req, res, next) => {
    try {
        const { fullName } = req.body;
        const { id } = req.user;

        console.log(fullName);

        const user = await User.findById(id);

        if (!user) {
            return next(new AppError("user does not exist", 400));
        }

        if (fullName) {
            user.fullName = fullName
        }

        if (req.file) {
            await cloudinary.v2.uploader.destroy(user.avatar.public_id);

            try {
                const result = await cloudinary.v2.uploader.upload(req.file.path, {
                    folder: 'lms',
                    width: 250,
                    height: 250,
                    gravity: 'faces',
                    crop: 'fill'
                })

                if (result) {
                    user.avatar.public_id = result.public_id;
                    user.avatar.secure_url = result.secure_url;

                    // Remove file from server
                    fs.rmSync(`uploads/${req.file.filename}`);

                }
            } catch (e) {
                return next(new AppError(e.message || 'File not uploaded, please try again', 500))
            }
        }

        await user.save();

        res.status(200).json({
            success: true,
            message: "User update successfully",
            user
        })
    } catch (e) {
        return next(new AppError(e.message, 500))
    }

}

// OAuth methods
export const googleAuth = passport.authenticate('google', { scope: ['profile', 'email'] });

export const googleAuthCallback = (req, res, next) => {
    passport.authenticate('google', { failureRedirect: '/login' }, (err, user) => {
        if (err) {
            console.error('Google Auth Error:', err);
            return res.redirect('/login');
        }
        if (!user) {
            console.error('No user returned from Google Auth');
            return res.redirect('/login');
        }
        req.logIn(user, (err) => {
            if (err) {
                console.error('Login Error:', err);
                return res.redirect('/login');
            }
            const token = user.generateJWTToken();
            res.cookie('token', token, cookieOptions);
            return res.redirect(`${process.env.CLIENT_URL}/profile`);
        });
    })(req, res, next);
};

// Similar update for githubAuthCallback

// GitHub OAuth Callback
export const githubAuth = passport.authenticate('github', { scope: ['user:email'] });

export const githubAuthCallback = passport.authenticate('github', {
    failureRedirect: '/login',
    session: true
}, (req, res) => {
    const token = req.user.generateJWTToken();
    res.cookie('token', token, cookieOptions);
    res.redirect(`${process.env.CLIENT_URL}/profile`);
});


// Export updated functions
export {
    register,
    login,
    logout,
    getProfile,
    changePassword,
    updateUser,
    forgotPassword,
    resetPassword,

    // other methods...
};