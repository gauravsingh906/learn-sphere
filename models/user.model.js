import { Schema, model } from "mongoose";
import bcrypt from 'bcryptjs';
import jwt from "jsonwebtoken";
import crypto from 'crypto';

const userSchema = new Schema({
    fullName: {
        type: String,
        required: [true, "Name is required"],
        minLength: [5, "Name must be at least 5 characters"],
        maxLength: [50, 'Name should be less than 50 characters'],
        lowercase: true,
        trim: true,
    },
    email: {
        type: String,
        required: [true, "Email is required"],
        lowercase: true,
        trim: true,
        unique: true,
        match: [
            /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
            'Please fill in a valid Email Address'
        ]
    },
    password: {
        type: String,
        required: [function () { return !this.googleId && !this.githubId; }, 'Password is required for non-OAuth users'],
        minLength: [8, 'Password must be at least 8 characters'],
        select: false
    },
    avatar: {
        public_id: String,
        secure_url: String
    },
    role: {
        type: String,
        enum: ['USER', 'ADMIN'],
        default: 'USER'
    },
    forgetPasswordToken: String,
    forgetPasswordExpiry: Date,
    googleId: {
        type: String,
        unique: true,
        sparse: true
    },
    githubId: {
        type: String,
        unique: true,
        sparse: true
    },
    isEmailVerified: {
        type: Boolean,
        default: false
    },
    subscription: {
        id: String,
        status: String
    }
}, { timestamps: true });

userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 10);
    next();
});

userSchema.methods.generateJWTToken = async function () {
    return jwt.sign({
        id: this._id,
        email: this.email,
        role: this.role,
        subscription: this.subscription
    }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRY
    });
};

userSchema.methods.comparePassword = async function (plainTextPassword) {
    return bcrypt.compare(plainTextPassword, this.password);
};

userSchema.methods.generatePasswordResetToken = async function () {
    const resetToken = crypto.randomBytes(20).toString('hex');
    this.forgetPasswordToken = crypto
        .createHash('sha256')
        .update(resetToken)
        .digest('hex');
    this.forgetPasswordExpiry = Date.now() + 15 * 60 * 1000; // 15 min expiry
    return resetToken;
};

userSchema.statics.findOrCreateGoogleUser = async function (profile) {
    let user = await this.findOne({ googleId: profile.id });
    if (!user) {
        user = await this.create({
            fullName: profile.displayName,
            email: profile.emails[0].value,
            googleId: profile.id,
            avatar: { secure_url: profile.photos[0].value },
            isEmailVerified: true
        });
    }
    return user;
};

userSchema.statics.findOrCreateGithubUser = async function (profile) {
    let user = await this.findOne({ githubId: profile.id });
    if (!user) {
        user = await this.create({
            fullName: profile.displayName || profile.username,
            email: profile.emails[0].value,
            githubId: profile.id,
            avatar: { secure_url: profile.photos[0].value },
            isEmailVerified: true
        });
    }
    return user;
};

const User = model('User', userSchema);
export default User;