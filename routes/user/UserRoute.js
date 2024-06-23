const express = require("express");
const {
  userRegisterCtrl,
  userLoginCtrl,
  updatePasswordCtrl,
  forgotPasswordCtrl,
  resetPasswordCtrl,
} = require("../../controllers/users/userCtrl");
const isAdmin = require("../../middlewares/isAdmin");
const userRouter = express.Router();

//POST/api/v1/users/register
userRouter.post("/register", userRegisterCtrl);

//POST/api/v1/users/login
userRouter.post("/login", userLoginCtrl);

//PUT/api/v1/users/updatePassword
userRouter.put("/updatePassword", updatePasswordCtrl);

userRouter.post('/forgotPassword', forgotPasswordCtrl);
userRouter.post('/resetPassword', resetPasswordCtrl);

module.exports = userRouter;