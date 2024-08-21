
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
    check("password").isLength({ min: 6 }).withMessage("Password must be at least 6 characters long")
  ],
  async (req, res) => {
    const { login, email, password, confirm_password } = req.body;
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    if (password !== confirm_password) {
      return res.status(400).json({ error: "Passwords do not match" });
    }

    try {
      const user = await User.add_user({ login, email, password });
      res.status(201).json({ message: "User registered successfully", user });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);



user_router.post("/signin", async (req, res) => {
  const { login, password } = req.body;

  try {
    
    const user = await User.findUserByLogin(login);

    if (!user) {
      return res.status(401).json({ error: "User not found" });
    }

    
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

 
    const accessToken = secure.generateToken({ id: user.id, login: user.login });

 
    res.cookie('access', accessToken, { httpOnly: true });

    res.status(200).json({ message: "User authenticated successfully", token: accessToken });
  } catch (error) {
    res.status(500).json({ error: error.message });
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
