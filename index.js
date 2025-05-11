import { countryCode, countryClasses } from "./countryCode.js";
import express from "express";
import dotenv from "dotenv";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import passport from "passport";
import pg from "pg";
import session from "express-session";
import { Strategy } from "passport-local";

const app = express();
const port = 3000;
const saltRounds = 10

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
dotenv.config()
console.log(process.env.SESSION_SECRET)

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { 
    secure: false,
    maxAge: 1000 * 60 * 60 * 24, 
  }
}));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});
db.connect();

var countriesId = []
var countriesClass = []
var invalidName = "";
var allCountries = [];
var actualName = "";
var invalidUserInput;
var invalidBool = false;

//World Map
app.get("/", async (req, res) => {
  if (req.isAuthenticated()) {
    console.log("my session: ", req.session.passport.user)
    countriesId = []
    countriesClass = []
    try {
      const actualUser = (await db.query("SELECT id, color FROM users WHERE name = $1", [req.user.name])).rows[0];
      const userId = actualUser.id;
      var color = actualUser.color;
      const countryIds = (await db.query("SELECT country_id FROM countries WHERE user_id = $1", [userId])).rows;
      const filterId = (countryIds.filter((country) => country.country_id != null))
      filterId.forEach((country) => countriesId.push(country.country_id))
      const countriesClasses = (await db.query("SELECT country_class FROM countries WHERE user_id = $1", [userId])).rows;
      const filterClass = (countriesClasses.filter((country) => country.country_class != null))
      filterClass.forEach((country) => countriesClass.push(country.country_class))
    } catch(err) {
      console.log(err);
    }
    updateVisitedCountries(countriesId, countriesClass);
    if(!invalidBool) invalidUserInput = null
    else invalidBool = false;
    console.log("aaaa, ", invalidUserInput)
    res.render("index.ejs", {countriesId: countriesId, countriesClass: countriesClass, invalidName: invalidName, allCountries: allCountries, userName: actualName, color: color, invalidUserInput: invalidUserInput}) 
  } else {
    res.render("index.ejs", {userName: "Sign in"})
  }
});
//Login
app.get("/login", async (req, res) => {
  //Set invalid variables to null if the user reloads the page.
  if(!invalidBool) invalidUserInput = null
  else invalidBool = false;
  res.render("login.ejs", {invalidUserInput: invalidUserInput})
});

//Register
app.get("/register", async (req, res) => {
  //Set invalid variables to null if the user reloads the page.
  if(!invalidBool) invalidUserInput = null
  else invalidBool = false;
  res.render("register.ejs", {invalidUserInput: invalidUserInput});
});

//Add country
app.post("/add", async (req, res) => {
    if(req.isAuthenticated()) {
      try {
        const userId = (await db.query("SELECT id FROM users WHERE name = $1", [req.user.name])).rows[0].id;
        console.log(userId)
        //check if exists id in countryCode
        const country = req.body.country;
        if (getKeyByValue(countryCode, country.toLowerCase())) {
          const countryIndex = getKeyByValue(countryCode, country.toLowerCase())
          invalidName = ""
          if (!countriesId.includes(countryIndex)) {
            await db.query("INSERT INTO countries (country_id, user_id) VALUES ($1, $2)", [countryIndex, userId]);
          }
        } else if (countryCode[country.toUpperCase()]) {
          invalidName = ""
          if (!countriesId.includes(country.toUpperCase())) {
            await db.query("INSERT INTO countries (country_id, user_id) VALUES ($1, $2)", [country.toUpperCase(), userId]);
          }
        // check if exists class in countryClasses
        } else {
          const keys = Object.keys(countryClasses)
          const values = Object.values(countryClasses)
          if (keys.includes(country.toUpperCase())) {
            const selectedCountry = countryClasses[country.toUpperCase()]
            if (!countriesClass.includes(selectedCountry)) {
              await db.query("INSERT INTO countries (country_class, user_id) VALUES ($1, $2)", [selectedCountry, userId]);
            }
          } else if (values) {
            const lowerCaseValues = values.map(value => value.toLowerCase())
            if (lowerCaseValues.includes(country.toLowerCase())) {
              const id = lowerCaseValues.findIndex(value => value === country.toLowerCase())
              if (!countriesClass.includes(values[id])) {
                await db.query("INSERT INTO countries (country_class, user_id) VALUES ($1, $2)", [values[id], userId]);
              }
            }
            else {
              invalidName = "INVALID NAME"
              console.log("incorrect name")
            }
          }
        }
        } catch(err) {
          console.log(err)
        }
      res.redirect("/")
    } else {
      res.redirect("/login")
    }
});

//Delete country
app.post("/deleteCountry", async (req, res) => {
  if(req.isAuthenticated()) {
    try {
      const userId = (await db.query("SELECT id FROM users WHERE name = $1", [req.user.name])).rows[0].id;
      console.log(userId)
      const country = req.body.country;
      if (getKeyByValue(countryCode, country.toLowerCase())) {
        const countryIndex = getKeyByValue(countryCode, country.toLowerCase())
        invalidName = ""
        if (countriesId.includes(countryIndex)) {
          await db.query("DELETE  FROM countries * WHERE country_id = $1 AND user_id = $2", [countryIndex, userId]);
        }
      } else if (countryCode[country.toUpperCase()]) {
        invalidName = ""
        if (countriesId.includes(country.toUpperCase())) {
          await db.query("DELETE  FROM countries * WHERE country_id = $1 AND user_id = $2", [country.toUpperCase(), userId]);
        }
      // check if exists class in countryClasses
      } else {
        const keys = Object.keys(countryClasses)
        const values = Object.values(countryClasses)
        if (keys.includes(country.toUpperCase())) {
          const selectedCountry = countryClasses[country.toUpperCase()]
          if (countriesClass.includes(selectedCountry)) {
            await db.query("DELETE  FROM countries * WHERE country_class = $1 AND user_id = $2", [selectedCountry, userId]);
          }
        } else if (values) {
          const lowerCaseValues = values.map(value => value.toLowerCase())
          if (lowerCaseValues.includes(country.toLowerCase())) {
            const id = lowerCaseValues.findIndex(value => value === country.toLowerCase())
            if (countriesClass.includes(values[id])) {
              await db.query("DELETE  FROM countries * WHERE country_class = $1 AND user_id = $2", [values[id], userId]);
            }
          }
          else {
            invalidName = "INVALID NAME"
            console.log("incorrect name")
          }
        }
      }
    } catch(err) {
      console.log(err)
    }
  res.redirect("/")
  }
});

app.post("/visitedCountries", (req, res) => {
  console.log(req.body.visitedCountries)
  res.redirect("/")
});

//Register request
app.post("/register", async (req, res) => {
  const userName = req.body.username;
  const userPassword = req.body.password;
  const userConfirmPassword = req.body.confirmpassword;
  const choosenColor = req.body.choosecolor;
  if (userName && userPassword && userConfirmPassword && choosenColor) {
    try {
      const checkUser = await db.query("SELECT * FROM users WHERE name = $1", [userName])
      console.log(checkUser.rows)
      if (checkUser.rows.length > 0) {
        invalidBool = true;
        invalidUserInput = "This name is already taken.";
        res.redirect("/register")
      } else if (userPassword === userConfirmPassword) {
        //Generate salt
          bcrypt.genSalt(saltRounds, (err, salt) => {
            if (err) {
                console.log(err)
            } else {
              // Salt generation successful, proceed to hash the password
              bcrypt.hash(userPassword, salt, async (err, hash) => {
                if (err) {
                  console.error("Error hashing password:", err);
                } else {
                console.log('Hashed password:', hash);
              const result = await db.query("INSERT INTO users (name, password, color) VALUES ($1, $2, $3) RETURNING *", [userName, hash, choosenColor])
              const user = result.rows[0];
              actualName = user.name;
              req.login(user, (err) => {
                console.log(err)
                res.redirect("/")
              });
            } 
            });
          }
          });
      } else {
        invalidBool = true;
        invalidUserInput = "Confirm password is not equal!";
        console.log("Password and confirm password is not equal!");
        res.redirect("/register")
      }
    console.log(req.body)
    } catch(err) {
      console.log(err)
    }
  } else {
    invalidBool = true;
    invalidUserInput = "You have to fill all inputs.";
    console.log("You have to fill all inputs")
    res.redirect("/register")
  }
});

//Login request
app.post("/login", (req, res, next) => {
  if (!req.body.username || !req.body.password) {
  invalidBool = true;
  invalidUserInput = "You have to fill all inputs."
  res.redirect("/login");
  } else {next()}
},
  passport.authenticate("local", {
  successRedirect: "/",
  failureRedirect: "/login"
})
);

//log out user
app.post("/logOut", (req, res) => {
  req.logout((err) => {
    if (err) console.log(err)
      res.redirect("/")
  })
});

//update user
app.post("/updateUser", async (req, res) => {
  if(req.isAuthenticated()) {
    const newName = req.body.username;
    const newPassword = req.body.password;
    const confirmPassword = req.body.confirmpassword;
    const chooseColor = req.body.choosecolor;
    const storedHashedPassword = req.user.password;
    const storedUserName = req.user.name;
    const storedUserColor = req.user.color;
    if (confirmPassword && newName) {
      bcrypt.compare(confirmPassword, storedHashedPassword, async (err, result) => {
        if (err) {
            // Handle error
            console.log('There was a problem somewhere');
        } else {
          if (result) {
              // Passwords match, authentication successful
              console.log('Password is correct! User authenticated.');
              try{
                //Check if the user want to change name.
                const checkNamePassword = await db.query("SELECT * FROM users WHERE name = $1 AND password = $2", [newName, storedHashedPassword]);
                if(checkNamePassword.rows.length > 0) {
                  console.log("Name is the same, no change.");
                } else {
                  const checkName = await db.query("SELECT * FROM users WHERE name = $1", [newName]);
                  if(checkName.rows.length > 0) {
                    console.log("The name is already in use, please choose another.");
                  } else {
                    await db.query("UPDATE users SET name = $1 WHERE password = $2", [newName, storedHashedPassword]);
                    //update actualName and passport
                    actualName = newName;
                    req.session.passport.user.name = newName;
                    req.session.save((err) => {
                      if(err) console.log(err);
                        else {
                          console.log("User name is updated, new name is: ", newName);
                        }
                    });
                 
                  }
                }
                //Check if user want to change password.
                if (confirmPassword === newPassword) {
                  console.log("Passwords are the same.")
                } else {
                  //Hash and save new password.
                  bcrypt.genSalt(saltRounds, (err, salt) => {
                    if (err) {
                        console.log(err)
                    } else {
                      // Salt generation successful, proceed to hash the password
                      bcrypt.hash(newPassword, salt, async (err, hash) => {
                        if (err) {
                          console.error("Error hashing password:", err);
                        } else {
                        console.log('Hashed password:', hash);
                        await db.query("UPDATE users SET password = $1 WHERE name = $2", [hash, storedUserName]);
                        req.session.passport.user.password = hash;
                        req.session.save((err) => {
                        if(err) console.log(err);
                        else {
                          
                          console.log("Password was updated, new hashed password is: ", hash);
                        }
                    });
                    } 
                    });
                  }
                  });
                }
                //Check if user want to change color.
                if (chooseColor === storedUserColor) {
                    console.log("Colors are the same.")
                } else {
                  req.session.passport.user.color = chooseColor;
                  req.session.save( async (err) => {
                  if(err) console.log(err);
                        else {
                          await db.query("UPDATE users SET color = $1 WHERE name = $2", [chooseColor, newName]);
                          console.log("Color was updated, new color is: ", chooseColor);
                        }
                    });
                }
              } catch(err) {
                console.log(err);
              }
            } else {
              // Passwords don't match, authentication failed
              invalidBool = true;
              invalidUserInput = 'Old password is not correct!';
          } 
        }
      });
    } else {
      invalidBool = true;
      invalidUserInput = "You have to fill name and old password input!";
      console.log("You have to fill name and old password input!")
    }
    //redirect after user session is changed.
    setTimeout(() => {  res.redirect("/"); }, 100);
  }
  });
//delete user
app.post("/deleteUser", (req, res) => {
  if(req.isAuthenticated()) {
    db.query("DELETE FROM users * WHERE name = $1",[req.user.name]);
    req.logout((err) => {
      if (err) console.log(err)
        console.log("User account was deleted.")
        res.redirect("/")
    })
  }
});

function updateVisitedCountries(countriesId, countriesClass) {
  allCountries = [];
  countriesId.forEach(countryId => {
    allCountries.push(countryCode[countryId]+" ("+ countryId +")")
  });
  countriesClass.forEach((countryC) => {
    allCountries.push(countryC + " ("+ getKeyByValue(countryClasses, countryC.toLowerCase()) + ")")
  })
  return allCountries;
}

function getKeyByValue(object, value) {
    return Object.keys(object).find(key =>
        object[key].toLowerCase() === value);
}

//login user with passport
passport.use(new Strategy( async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE name = $1", [username])
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        console.log(storedHashedPassword);
        bcrypt.compare(password, storedHashedPassword, (err, result) => {
          if (err) {
              // Handle error
              return cb(err);
          } else {
            if (result) {
                // Passwords match, authentication successful
                console.log('Passwords match! User authenticated.');
                console.log(user)
                actualName = user.name;
                return cb(null, user);
            } else {
                invalidUserInput = "Incorrect password!";
                invalidBool = true;
                return cb(null, false);
            } 
          }
        });
      } else {
        invalidUserInput = "User not found!";
        invalidBool =  true;
        return cb(null, false)
      }
    } catch(err) {
      return cb(err);
    }
   
  }
));

passport.serializeUser((user, cb) => {
  cb(null, user)
});

passport.deserializeUser((user, cb) => {
  cb(null, user)
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
