const jwt = require("jsonwebtoken");
const User = require("../models/User");

const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || "7d",
  });
};

// @route  POST /api/auth/register
exports.register = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ success: false, message: "All fields are required" });
    }

    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(409).json({ success: false, message: "Email already registered" });
    }

    const user = await User.create({ name, email, password });

    return res.status(201).json({
      success: true,
      token: generateToken(user._id),
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        avatarInitial: user.avatarInitial,
        role: user.role,
      },
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
};

// @route  POST /api/auth/login
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log(`[LOGIN ATTEMPT] email="${email}"`);

    if (!email || !password) {
      console.log("[LOGIN FAILED] missing email or password in request");
      return res.status(400).json({ success: false, message: "Email and password are required" });
    }

    const user = await User.findOne({ email: email.toLowerCase() }).select("+password");
    if (!user) {
      console.log(`[LOGIN FAILED] no user found with email "${email.toLowerCase()}"`);
      return res.status(401).json({ success: false, message: "Invalid email or password" });
    }
    const passwordMatches = await user.matchPassword(password);
    if (!passwordMatches) {
      console.log(`[LOGIN FAILED] password did not match for "${email.toLowerCase()}"`);
      return res.status(401).json({ success: false, message: "Invalid email or password" });
    }
    console.log(`[LOGIN SUCCESS] "${email.toLowerCase()}"`);

    return res.status(200).json({
      success: true,
      token: generateToken(user._id),
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        avatarInitial: user.avatarInitial,
        role: user.role,
      },
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
};

// @route  GET /api/auth/me
exports.getMe = async (req, res) => {
  return res.status(200).json({
    success: true,
    user: {
      id: req.user._id,
      name: req.user.name,
      email: req.user.email,
      avatarInitial: req.user.avatarInitial,
      role: req.user.role,
    },
  });
};

// @route  POST /api/auth/logout (client just discards token; endpoint kept for parity)
exports.logout = async (req, res) => {
  return res.status(200).json({ success: true, message: "Logged out successfully" });
};
