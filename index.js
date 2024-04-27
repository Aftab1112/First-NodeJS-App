import express from "express";
import path from "path";
import mongoose from "mongoose";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

// Defining host, port & database name
const hostName = "localhost";
const port = 5000;
const dataBaseName = "Backend";

// Mongo server address
const mongoServer = `mongodb://${hostName}:27017/${dataBaseName}`;

// Connecting to MongoDB
const connectToMongoDB = async () => {
  try {
    await mongoose.connect(mongoServer);
    console.log("Connected to MongoDb");
  } catch (err) {
    console.log(err);
  }
};
connectToMongoDB();

// Creating a Schema for users
const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
});

// Creating a collection
const user = new mongoose.model("user", userSchema);

// Creating a basic express server
const app = express();

// Using middlewares
app.use(express.static(path.join(path.resolve(), "public")));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Setting view engine to render files from view folder
app.set("view engine", "ejs");

// Created shortcut / middleware for authentication before rendering actual home page
const isAuthenticated = async (req, res, next) => {
  const { token } = req.cookies;
  if (token) {
    const decodedData = jwt.verify(token, "privateKey");
    req.user = await user.findById(decodedData._id);
    next();
  } else {
    res.redirect("/login");
  }
};

// Render Register page
app.get("/register", (req, res) => {
  res.render("register");
});

// Render Login page
app.get("/login", (req, res) => {
  res.render("login");
});

// Render Logout page
app.get("/", isAuthenticated, (req, res) => {
  res.render("logout", { name: req.user.name });
});

// If user is already registered make him login using mail and password
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  let registeredUser = await user.findOne({ email });
  if (!registeredUser) return res.redirect("/register");

  // Checking if password matches
  const isMatch = await bcrypt.compare(password, registeredUser.password);

  // If password dosent match re-render login page again with error message
  if (!isMatch) {
    return res.render("login", { email, message: "Incorrect Password" });
  }

  // If password matches create token and redirect him to login page
  const token = jwt.sign({ _id: registeredUser._id }, "privateKey");

  res.cookie("token", token, {
    httpOnly: true,
    expires: new Date(Date.now() + 60 * 1000),
  });
  res.redirect("/");
});

// Registering a new user
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  // Checking if user already exists in database ,  if exist then redirect user to login page
  let newUser = await user.findOne({ email });
  if (newUser) return res.redirect("/login");

  // Bcrypting password before registering user
  const hashedPassword = await bcrypt.hash(password, 10);

  // If user not exists creating a new user in database
  newUser = await user.create({
    name,
    email,
    password: hashedPassword,
  });

  // Creating token to store in browser cookie
  const token = jwt.sign({ _id: newUser._id }, "privateKey");

  res.cookie("token", token, {
    httpOnly: true,
    expires: new Date(Date.now() + 60 * 1000),
  });
  res.redirect("/");
});

// Creating logut
app.get("/logout", (req, res) => {
  res.cookie("token", null, {
    httpOnly: true,
    expires: new Date(Date.now()),
  });
  res.redirect("/");
});

// Listen on server
app.listen(port, () => {
  console.log(`Server is running on http://${hostName}:${port}`);
});
