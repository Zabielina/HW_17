import { Router } from "express";
import User from "../postgres/models/User.js";
import { check, validationResult } from "express-validator";
import user from "../services/user-service.js";
import secure from "../services/user-secure.js";
const user_router = Router();
user_router.get("/signup", (req, res) => {
  res.render("form_register", { title: "Registration Form" });
});

user_router.get("/signin", (req, res) => {
  res.render("form_auth", { title: "Auth Form" });
});


user_router.delete("/:id", async(req, res) => {
  const id = req.params.id
  await User.delete_users(id);
res.redirect("/")

 
});




user_router.get("/list", async(req, res) => {
  const list_users = await User.get_all_users();
  console.log(list_users);
  
   res.render("user_list", { title: "User list" ,users: list_users});
 });





user_router.post(
  "/signup",
  [
    check("email").isEmail().withMessage("Введіть правильний email"),
    check("login").isLength({ min: 6, max: 20 }).withMessage("Невірний логін"),
  ],

  async (req, res) => {
    const { login, email, password, confirm_password } = req.body;
    const errors = validationResult(req);
    if (errors.isEmpty() && password === confirm_password) {
      await User.add_user(req.body);
      req.session.user = login;
      req.session.email = email;
      user.add(login, email, password);
      // res.cookie("user", login);
      // //res.cookie("email", email, { maxAge: 1000000, httpOnly:true });
      // res.cookie("email", email);
      console.log(login, email, password);
      res.redirect("/");
      return;
    }
    res.json({ errors: errors.array() });
  }
);

user_router.get("/logout", (req, res) => {
  // res.clearCookie("user");
  // res.clearCookie("email");
  req.session.destroy();
  res.redirect("/");
});

//JWT
/*
{
  "login":"your login",
  "email":"email",
  "password":"123",
  "confirm_password":"123"
}
*/

user_router.post("/", (req, res) => {
  const { login, email, password, confirm_password } = req.body;
  if (login.length > 3 && password === confirm_password) {
    const token = secure.generateToken(req.body);
    res.json({ token: token });
  } else {
    res.send("Error");
  }
});

user_router.get("/", secure.authenticateToken, (req, res) => {
  res.send(req.user);
});
export default user_router;
