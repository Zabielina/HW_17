
import { Router } from "express";
import { check, validationResult } from "express-validator";
import User from "../postgres/models/User.js";
import secure from "../services/user-secure.js";

const user_router = Router();


user_router.get("/signup", (req, res) => {
  res.render("form_register", { title: "Registration Form" });
});

user_router.post(
  "/signup",
  [
    check("email").isEmail().withMessage("Enter a valid email"),
    check("login").isLength({ min: 6 }).withMessage("Login must be at least 6 characters long"),
    check("password").isLength({ min: 6 }).withMessage("Password must be at least 6 characters long"),
    check("confirm_password").custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error("Passwords do not match");
      }
      return true;
    })
  ],
  async (req, res) => {
    const { login, email, password } = req.body;
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const user = await User.add_user({ login, email, password });
      res.status(201).json({ message: "User registered successfully", user });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);


user_router.post("/signin", [
  check("login").notEmpty().withMessage("Login is required"),
  check("password").notEmpty().withMessage("Password is required")
], async (req, res) => {
  const { login, password } = req.body;
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const user = await User.authenticate_user(login, password);

    
    const accessToken = secure.generateToken({ id: user.id, login: user.login });
    res.cookie('access', accessToken, { httpOnly: true });

    res.status(200).json({ message: "User authenticated successfully", token: accessToken });
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
});


user_router.get("/signin", (req, res) => {
  res.render("form_auth", { title: "Authentication Form" });
});

user_router.get("/logout", (req, res) => {
  res.clearCookie("access");
  req.session.destroy();
  res.redirect("/");
});

user_router.get("/list", async (req, res) => {
  try {
    const users = await User.get_all_users();
    res.render("user_list", { title: "User list", users });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

export default user_router;
