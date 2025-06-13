const User = require('../models/User');
const emailSender = require('./emailSender');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const passwordGenerator = require('./passwordGenerator');
dotenv.config();



const JWT_SECRET = process.env.JWT_SECRET;


const register = async (req, res) => {
    const { email, login, password } = req.body;
    try {
        const exists = await User.findOne({ $or: [{ email }, { login }] });
        if (exists) {
            return res.status(400).json({ error: 'User already exists' });
        }
        const newUser = new User({
            email,
            login,
            password,
            image: req.file ? req.file.path : undefined,
            role: "user"
        });
        await newUser.save();
        const userObj = newUser.toObject();
        delete userObj.password;
        res.status(201).json(userObj);
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
}
const login = async (req, res) => {
    const { loginOrEmail, password } = req.body;
    try {
        const user = await User.findOne({
            $or: [{ login: loginOrEmail }, { email: loginOrEmail }]
        });
        if (!user) return res.status(401).json({ error: 'Invalid credentials' });

        const isMatch = await user.comparePassword(password);
        if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });

        const { password: passwords, ...userData } = user.toObject();

        const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });

        res.cookie('token', token, {
            httpOnly: true,
            sameSite: 'lax',
            maxAge: 60 * 60 * 1000
        });

        res.json({ user: userData });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
}
const logout = (req, res) => {
    res.clearCookie('token', {
        httpOnly: true,
        sameSite: 'lax'
    });
    res.json({ success: true });
}
const updatePassword = async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email: email });
        if (!user) return res.status(401).json({ error: 'Invalid credentials' });
        genPassword = passwordGenerator();
        emailSender(email, genPassword);
        res.status(201).json({ message: "Email sent." });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }

}

const getUsers = async (req, res) => {
    try {
        const users = await User.find().lean();

        res.json(users.map(u => {
            const { password, ...userWithoutPassword } = u;
            return userWithoutPassword;
        }));
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
}

const updateUser = async (req, res) => {
    try {

        if (req.user.role !== 'admin' && req.user.id !== req.params.id) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        const updateData = { ...req.body };
        if (req.file) {
            updateData.image = req.file.path;
        }
        if (updateData.password) {
            updateData.password = await bcrypt.hash(updateData.password, 10);
        } else {
            delete updateData.password;
        }
        const user = await User.findByIdAndUpdate(
            req.params.id,
            updateData,
            { new: true, runValidators: true }
        ).lean();
        if (!user) return res.status(404).json({ error: 'User not found' });
        const { password, ...userWithoutPassword } = user;
        res.json(userWithoutPassword);
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
};

const deleteUser = async (req, res) => {
    try {
        const user = await User.findByIdAndDelete(req.params.id);
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
}


module.exports = { register, login, logout, getUsers, updateUser, deleteUser, updatePassword }