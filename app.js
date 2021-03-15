var path = require('path')
const express = require("express");
require('dotenv').config();
const knex = require('knex');
const morgan = require("morgan");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt-nodejs");
const { Client } = require('pg');
const cors = require("cors");
const jwt = require("jsonwebtoken"); // to generate signed token
const expressJwt = require("express-jwt"); // for authorization check
const formidable = require("formidable");
const _ = require("lodash");
const fs = require("fs");
const multer = require("multer");

const db = new Client({
  user: 'postgres',
  host: 'localhost',
  database: 'ecom',
  password: 'goori',
  port: 5432,
})

db.connect()

// const postgres = knex({
//     client: 'pg',
//     connection: {
//       host : '127.0.0.1',
//       user : 'postgres',
//       password : 'goori',
//       database : 'ecom'
//     }
//   });

//   postgres.select("*").from("users").then(data => {
//       console.log(data);
//   });

const app = express();
app.use(cors());
app.use(express.json());
app.use(cookieParser());


// AUTH MIDDLEWARE

// WE CAN USE IT TO VERIFY THE USER IF HE HAS VALID TOKEN OR NOT
const requireSignin = expressJwt({
  secret: process.env.JWT_SECRET,
  algorithms: ["HS256"], // added later
  userProperty: "auth",
});


var storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, './public/images/');
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + file.originalname);
  }
});

var upload = multer({ storage: storage });

app.use(express.static(path.join(__dirname, 'public')));

// GET THE USER
app.param("userId", async (req,res,next) => {
  id = req.params.userId;
  try{
    const results = await db.query('SELECT * FROM users WHERE id=$1',[id]);

    req.profile = results.rows[0];
    if(!req.profile){
      return res.status(400).json({
        "err" : "User with that id does not found"
      });
    }  

    next();
  }catch(error){
    console.log(error);
  }
});

// GET THE CATEGORY BY ID
app.param("categoryId", async (req,res,next) => {
  id = req.params.categoryId;
  try{
    const results = await db.query('SELECT * FROM category WHERE id=$1',[id]);

    req.category = results.rows[0];
    if(!req.category){
      return res.status(400).json({
        "err" : "Category with that id does not found"
      });
    }  

    next();
  }catch(error){
    console.log(error);
  }
});


// GET THE PRODUCT BY ID
app.param("productId", async (req,res,next) => {
  id = req.params.productId;
  try{
    const results = await db.query('SELECT * FROM product WHERE id=$1',[id]);

    req.product = results.rows[0];
    if(!req.product){
      return res.status(400).json({
        "err" : "Product with that id does not found"
      });
    }  

    next();
  }catch(error){
    console.log(error);
  }
});





// CREATE A MIDDLEWARE FOR AUTHENTICATION
const isAuth = (req,res,next) => {
  let user = req.profile && req.auth && (req.profile.id === req.auth.id);
  if(!user){
    return res.status(403).json({
      error: "Access denied"
    });
  }
  next();
};


// MIDDLEWARE FOR ADMIN
const isAdmin = (req,res,next) => {
  if(req.profile.role === 0){
    return res.status(403).json({
      error: "Admin resource! Access denied"
    });
  }

  next();
};




// GET ALL USERS
app.get("/getUsers",async (req,res) => {
  // res.send("hi");
  const users = await (db.query("select * from users"));
  return res.status(200).json({
    status: "Success",
    results: users.rows.length, 
    data: {
        users: users.rows,
    },
});
});


// REGISTER A USER
app.post("/signup",async(req,res)=>{
  const {email,name,password} = req.body;
  const hash = bcrypt.hashSync(password);

  if(!email || !name ||!password){
    return res.status(400).json("Invalid form submission");
  }

  try{
    const results = await db.query('insert into users(name,email,password) VALUES ($1,$2,$3) returning *',[name,email,hash]);
    return res.status(200).json({
        status: "Success",
        results: results.rows.length, 
        data: {
            user: results.rows[0],
        },
    });
}catch(err){
    console.log(err);
}
});



// Signin a user
app.post("/signin",async(req,res)=>{
  const {email,password} = req.body;
  
  if(!email ||!password){
    return res.status(400).json("Invalid form submission");
  }
  try{
    const results = await db.query('SELECT * FROM users WHERE email=$1',[email]);

    if(!results){
      return res.status(400).json({
        "err" : "User with that email does not exist"
      });
    }

    console.log(results);

    // IF USER IS FOUND
    const isValid = bcrypt.compareSync(password, results.rows[0].password);

    

    if(isValid){

      const token = jwt.sign({id: results.rows[0].id},process.env.JWT_SECRET);
      res.cookie("t",token,{expire: new Date() + 9999 });


      return res.status(200).json({
        status: "Success",
        results: results.rows.length, 
        data: {
            user: results.rows[0],
            token: token
        },
      });
    }
    else{
      return res.status(400).json({
        "err Password" : "Wrong Password"
      });
    }
  
}catch(err){
  return res.status(400).json({
    "err" : "User with that email does not exist"
  });
}
});


//SIgn out user
app.get("/signout",(req,res)=>{
    res.clearCookie("t");
    res.json({
      'message': "Signout success"
    })
});



// FIND USER BY ID
app.get("/secret/:userId",requireSignin,async (req,res)=>{
  id = req.params.userId;
  try{
    // const results = await db.query('SELECT * FROM users WHERE id=$1',[id]);

    // if(!results){
    //   return res.status(400).json({
    //     "err" : "User with that id does not found"
    //   });
    // }  

    // req.profile = results.rows[0];
    
    // TO SEE IF USER IS ADMIN
    // if(req.profile.role === 1){
    //   return res.status(403).json({
    //     error: "Admin resource! Access denied"
    //   });
    // }

    // TO SEE IF USER HAS AUTHENTICATION
    // let user = req.profile && req.auth && req.profile.id === req.auth.id;
    //   if(!user){
    //     return res.status(403).json({
    //       error: "Access denied"
    //     });
    //   }

    console.log(req.profile);
    return res.json({
    
      user: req.profile
      
    });
    
} catch(err){
    return res.status(400).json({
     "err" : "USer with that id does not found"
    });
}
});







//CREATE A CATEGORY
app.post("/category/create/:userId",requireSignin,isAuth,isAdmin,async (req,res) => {
  // res.send("hi");
  try{
    // WE ALSO NEED TO SEE IF USER IS AUTHENTICATED
    // var id = req.params.userId;
  
    // const results1 = await db.query('SELECT * FROM users WHERE id=$1',[id]);

    // if(!results1){
    //   return res.status(400).json({
    //     "err" : "User with that id does not found"
    //   });
    // }  

    // req.profile = results1.rows[0];
    // TO SEE IF USER IS ADMIN
    // ADMIN IS ONE AND SAMPLE USER IS 0
    // if(req.profile.role === 0){
    //   return res.status(403).json({
    //     error: "Admin resource! Access denied"
    //   });
    // }

    // TO SEE IF USER HAS AUTHENTICATION
    // let user = req.profile && req.auth && req.profile.id === req.auth.id;
    //   if(!user){
    //     return res.status(403).json({
    //       error: "Access denied"
    //     });
    //   }


    const results = await db.query('insert into category(name) VALUES ($1) returning *',[req.body.name]);
    return res.status(200).json({
        status: "Success",
        results: results.rows.length, 
        data: {
            category: results.rows[0],
        },
    });
  }catch(err){
      console.log(err);
  }

});


//CREATE A PRODUCT
app.post("/product/create/:userId",requireSignin,isAuth,isAdmin,async (req,res) => {

  // res.send("hi");
  try{
    // WE ALSO NEED TO SEE IF USER IS AUTHENTICATED
    // var id = req.params.userId;
  
    // const results1 = await db.query('SELECT * FROM users WHERE id=$1',[id]);

    // req.profile = results1.rows[0];
    
    // if(!req.profile){
    //   return res.status(400).json({
    //     "err" : "User with that id does not found"
    //   });
    // }

    // TO SEE IF USER IS ADMIN
    // ADMIN IS ONE AND SAMPLE USER IS 0
    // if(req.profile.role === 0){
    //   return res.status(403).json({
    //     error: "Admin resource! Access denied"
    //   });
    // }

    // TO SEE IF USER HAS AUTHENTICATION
    // let user = req.profile && req.auth && req.profile.id === req.auth.id;
    //   if(!user){
    //     return res.status(403).json({
    //       error: "Access denied"
    //     });
    //   }

      let form = new formidable.IncomingForm();
      form.keepExtensions = true;
      form.parse(req, async(err,fields,files) => {
        if(err){
          return res.status(400).json({
            error: "Image could not be uploaded"
          });
        }


        //CHECK FOR ALL FIELDS
        const {name,description,price,category,quantity,sold,shipping} = fields;
        
        if(!name || !description || !price || !category || !quantity || !shipping){
          return res.status(404).json({
            error: "Invalid form data"
          });
        }


        // UPLOAD IMAGE
        if(files.photo){
          if(files.photo.size > 1000000){
            return res.status(400).json({
              error: "Image should be less than 1 mb"
            });
          }
          var oldpath = files.photo.path;
          var newpath = 'C:/Users/FRENDZ/Desktop/Ecom/public/' + files.photo.name;
          fs.rename(oldpath, newpath, function (err) {
            if (err) throw err;
            // res.write('File uploaded and moved!');
            // res.end();
          });
        }

        const results = await db.query('insert into product(name,description,price,quantity,sold,photo,shipping,category) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) returning *',[fields.name,fields.description,fields.price,fields.quantity,fields.sold,newpath,fields.shipping,fields.category]);

        // res.json({ fields, files });

        

        return res.status(200).json({
          status: "Success",
          results: results.rows.length, 
          data: {
              product: results.rows[0],
          },
      });
    });
    
  }catch(err){
      console.log(err);
  }

});


// PRODUCT BY ID
app.get("/product/:productId",async (req,res)=>{
  // id = req.params.productId;
  try{
    // const results = await db.query('SELECT * FROM product WHERE id=$1',[id]);

    // req.product = results.rows[0];
    
    // if(!req.product){
    //   return res.status(400).json({
    //     "err" : "Product with that id does not found"
    //   });
    // }
  
    // console.log(req.product);
    return res.json({
      product: req.product    
    });
    
} catch(err){
    return res.status(400).json({
     "err" : "Product with that id does not found"
    });
}
});


// DELETE A PRODUCT
app.delete("/product/:productId/:userId",requireSignin,isAuth,isAdmin ,async (req, res) => {
  try{
    // WE ALSO NEED TO SEE IF USER IS AUTHENTICATED
    // var id = req.params.userId;  
    // const results1 = await db.query('SELECT * FROM users WHERE id=$1',[id]);

    // req.profile = results1.rows[0];

    // if(!req.profile){
    //   return res.status(400).json({
    //     "err" : "User with that id does not found"
    //   });
    // }  

    // TO SEE IF USER IS ADMIN
    // ADMIN IS ONE AND SAMPLE USER IS 0
    // if(req.profile.role === 0){
    //   return res.status(403).json({
    //     error: "Admin resource! Access denied"
    //   });
    // }

    // TO SEE IF USER HAS AUTHENTICATION
    // let user = req.profile && req.auth && req.profile.id === req.auth.id;
    //   if(!user){
    //     return res.status(403).json({
    //       error: "Access denied"
    //     });
      // }


      // TO see if product with that id exist
      // WE ALSO NEED TO SEE IF USER IS AUTHENTICATED
    
    // const results2 = await db.query('SELECT * FROM product WHERE id=$1',[req.params.productId]);
      
    // req.product = results2.rows[0];

    // if(!req.product){
    //   return res.status(400).json({
    //     "err" : "Product with that id does not found"
    //   });
    // }  


        const results = await db.query('Delete from product where id=$1',[req.params.productId]);

        return res.status(204).json({
          results: results,
          status: 'success',
      });
    
  }catch(err){
      console.log(err);
  }

});

// UPDATE A PRODUCT
app.put("/product/update/:productId/:userId",requireSignin,isAuth,isAdmin, async (req, res) => {

  // res.send("hi");
  try{
    // WE ALSO NEED TO SEE IF USER IS AUTHENTICATED
    // var id = req.params.userId;
  
    // const results1 = await db.query('SELECT * FROM users WHERE id=$1',[id]);

    // req.profile = results1.rows[0];

    // if(!req.profile){
    //   return res.status(400).json({
    //     "err" : "User with that id does not found"
    //   });
    // }  

    // TO SEE IF USER IS ADMIN
    // ADMIN IS ONE AND SAMPLE USER IS 0
    // if(req.profile.role === 0){
    //   return res.status(403).json({
    //     error: "Admin resource! Access denied"
    //   });
    // }

    // // TO SEE IF USER HAS AUTHENTICATION
    // let user = req.profile && req.auth && req.profile.id === req.auth.id;
    //   if(!user){
    //     return res.status(403).json({
    //       error: "Access denied"
    //     });
    //   }

      // let pid = req.params.productId;
  
      // const results2 = await db.query('SELECT * FROM product WHERE id=$1',[pid]);
      
      // req.product = results2.rows[0];

      // if(!req.product){
      //   return res.status(400).json({
      //     "err" : "Product with that id does not found"
      //   });
      // }  


      let form = new formidable.IncomingForm();
      form.keepExtensions = true;
      form.parse(req, async(err,fields,files) => {
        if(err){
          return res.status(400).json({
            error: "Image could not be uploaded"
          });
        }


        //CHECK FOR ALL FIELDS
        const {name,description,price,category,quantity,sold,shipping} = fields;
        
        if(!name || !description || !price || !sold ||!category || !quantity || !shipping){
          return res.status(404).json({
            error: "Invalid form data"
          });
        }


        // UPLOAD IMAGE
        if(files.photo){
          if(files.photo.size > 1000000){
            return res.status(400).json({
              error: "Image should be less than 1 mb"
            });
          }
          var oldpath = files.photo.path;
          var newpath = 'C:/Users/FRENDZ/Desktop/Ecom/public/'+ files.photo.name;
          fs.rename(oldpath, newpath, function (err) {
            if (err) throw err;
            // res.write('File uploaded and moved!');
            // res.end();
          });
        }

        const results = await db.query('UPDATE product SET name=$1 , description= $2, price=$3, quantity=$4, sold=$5 ,photo=$6, shipping=$7, category=$8 WHERE id=$9 returning *',[fields.name,fields.description,fields.price,fields.quantity,fields.sold,newpath,fields.shipping,fields.category,req.params.productId]);

        // res.json({ fields, files });

        return res.status(200).json({
          status: "Success",
          results: results.rows.length, 
          data: {
              product: results.rows[0],
          },
      });
    });
    
  }catch(err){
      console.log(err);
  }

});


// GET CATEGORY BY ID
app.get("/category/:categoryId",async (req,res) => {
  try{
    return res.json({
      category: req.category    
    });
  } catch(error){
    console.log(error);
  } 
});



//UPDATE A CATEGORY
app.put("/category/:categoryId/:userId",requireSignin,isAuth,isAdmin,async (req,res) => {
  // res.send("hi");
  try{
    // WE ALSO NEED TO SEE IF USER IS AUTHENTICATED
    // var id = req.params.userId;
  
    // const results1 = await db.query('SELECT * FROM users WHERE id=$1',[id]);

    // if(!results1){
    //   return res.status(400).json({
    //     "err" : "User with that id does not found"
    //   });
    // }  

    // req.profile = results1.rows[0];
    // TO SEE IF USER IS ADMIN
    // ADMIN IS ONE AND SAMPLE USER IS 0
    // if(req.profile.role === 0){
    //   return res.status(403).json({
    //     error: "Admin resource! Access denied"
    //   });
    // }

    // TO SEE IF USER HAS AUTHENTICATION
    // let user = req.profile && req.auth && req.profile.id === req.auth.id;
    //   if(!user){
    //     return res.status(403).json({
    //       error: "Access denied"
    //     });
    //   }


    const results = await db.query('update category SET name=$1 where id=$2 returning *',[req.body.name,req.params.categoryId]);
    return res.status(200).json({
        status: "Success",
        results: results.rows.length, 
        data: {
            category: results.rows[0],
        },
    });
  }catch(err){
      console.log(err);
  }

});



//GET All CATEGORIES
app.get("/categories",async (req,res) => {
  // res.send("hi");
  try{
    // WE ALSO NEED TO SEE IF USER IS AUTHENTICATED
    // var id = req.params.userId;
  
    // const results1 = await db.query('SELECT * FROM users WHERE id=$1',[id]);

    // if(!results1){
    //   return res.status(400).json({
    //     "err" : "User with that id does not found"
    //   });
    // }  

    // req.profile = results1.rows[0];
    // TO SEE IF USER IS ADMIN
    // ADMIN IS ONE AND SAMPLE USER IS 0
    // if(req.profile.role === 0){
    //   return res.status(403).json({
    //     error: "Admin resource! Access denied"
    //   });
    // }

    // TO SEE IF USER HAS AUTHENTICATION
    // let user = req.profile && req.auth && req.profile.id === req.auth.id;
    //   if(!user){
    //     return res.status(403).json({
    //       error: "Access denied"
    //     });
    //   }


    const results = await db.query('SELECT * FROM category');
    return res.status(200).json({
        status: "Success",
        results: results.rows.length, 
        data: {
            category: results.rows,
        },
    });
  }catch(err){
      console.log(err);
  }

});





//DELETE A CATEGORY
app.delete("/category/:categoryId/:userId",requireSignin,isAuth,isAdmin,async (req,res) => {
  // res.send("hi");
  try{
    // WE ALSO NEED TO SEE IF USER IS AUTHENTICATED
    // var id = req.params.userId;
  
    // const results1 = await db.query('SELECT * FROM users WHERE id=$1',[id]);

    // if(!results1){
    //   return res.status(400).json({
    //     "err" : "User with that id does not found"
    //   });
    // }  

    // req.profile = results1.rows[0];
    // TO SEE IF USER IS ADMIN
    // ADMIN IS ONE AND SAMPLE USER IS 0
    // if(req.profile.role === 0){
    //   return res.status(403).json({
    //     error: "Admin resource! Access denied"
    //   });
    // }

    // TO SEE IF USER HAS AUTHENTICATION
    // let user = req.profile && req.auth && req.profile.id === req.auth.id;
    //   if(!user){
    //     return res.status(403).json({
    //       error: "Access denied"
    //     });
    //   }


    const results = await db.query('Delete from category where id=$1',[req.params.categoryId]);
    return res.status(200).json({
        status: "Success",
        results: results.rows.length, 
        data: {
            category: results.rows[0],
        },
    });
  }catch(err){
      console.log(err);
  }

});


//GET All PRODUCTS
// app.get("/products",async (req,res) => {
//   // res.send("hi");
//   try{
//     // WE ALSO NEED TO SEE IF USER IS AUTHENTICATED
//     // var id = req.params.userId;
  
//     // const results1 = await db.query('SELECT * FROM users WHERE id=$1',[id]);

//     // if(!results1){
//     //   return res.status(400).json({
//     //     "err" : "User with that id does not found"
//     //   });
//     // }  

//     // req.profile = results1.rows[0];
//     // TO SEE IF USER IS ADMIN
//     // ADMIN IS ONE AND SAMPLE USER IS 0
//     // if(req.profile.role === 0){
//     //   return res.status(403).json({
//     //     error: "Admin resource! Access denied"
//     //   });
//     // }

//     // TO SEE IF USER HAS AUTHENTICATION
//     // let user = req.profile && req.auth && req.profile.id === req.auth.id;
//     //   if(!user){
//     //     return res.status(403).json({
//     //       error: "Access denied"
//     //     });
//     //   }


//     const results = await db.query('SELECT * FROM product');
//     return res.status(200).json({
//         status: "Success",
//         results: results.rows.length, 
//         data: {
//             product: results.rows,
//         },
//     });
//   }catch(err){
//       console.log(err);
//   }

// });



// SEARCH PRODUCT BASED ON SELL AND ARIVAL
// by sell=/products?sortBy=sold&order=desc&limit=4
// by arrival=/products?sortBy=createdAt&order=desc&limit=4


//GET All PRODUCTS
app.get("/products",async (req,res) => {
  // res.send("hi");
  try{

    // GRAB ALL THE REQUEST PARAMETERS
    let order = req.query.order ? req.query.order : 'asc';
    let sortBy = req.query.sortBy ? req.query.sortBy : 'id';
    let limit = req.query.limit ? parseInt(req.query.limit) : 6;




    // WE ALSO NEED TO SEE IF USER IS AUTHENTICATED
    // var id = req.params.userId;
  
    // const results1 = await db.query('SELECT * FROM users WHERE id=$1',[id]);

    // if(!results1){
    //   return res.status(400).json({
    //     "err" : "User with that id does not found"
    //   });
    // }  

    // req.profile = results1.rows[0];
    // TO SEE IF USER IS ADMIN
    // ADMIN IS ONE AND SAMPLE USER IS 0
    // if(req.profile.role === 0){
    //   return res.status(403).json({
    //     error: "Admin resource! Access denied"
    //   });
    // }

    // TO SEE IF USER HAS AUTHENTICATION
    // let user = req.profile && req.auth && req.profile.id === req.auth.id;
    //   if(!user){
    //     return res.status(403).json({
    //       error: "Access denied"
    //     });
    //   }


    const results = await db.query('SELECT * FROM product ORDER BY '+ sortBy + ' ' + order +' LIMIT $1',[limit]);
    return res.status(200).json({
        status: "Success",
        results: results.rows.length, 
        data: {
            product: results.rows,
        },
    });
  }catch(err){
      console.log(err);
  }

});


// GET RELATED PRODUCTS
app.get("/products/related/:productId",async (req,res) => {
  // res.send("hi");
  try{

    // GRAB ALL THE REQUEST PARAMETERS
    let limit = req.query.limit ? parseInt(req.query.limit) : 6;




    // WE ALSO NEED TO SEE IF USER IS AUTHENTICATED
    // var id = req.params.userId;
  
    // const results1 = await db.query('SELECT * FROM users WHERE id=$1',[id]);

    // if(!results1){
    //   return res.status(400).json({
    //     "err" : "User with that id does not found"
    //   });
    // }  

    // req.profile = results1.rows[0];
    // TO SEE IF USER IS ADMIN
    // ADMIN IS ONE AND SAMPLE USER IS 0
    // if(req.profile.role === 0){
    //   return res.status(403).json({
    //     error: "Admin resource! Access denied"
    //   });
    // }

    // TO SEE IF USER HAS AUTHENTICATION
    // let user = req.profile && req.auth && req.profile.id === req.auth.id;
    //   if(!user){
    //     return res.status(403).json({
    //       error: "Access denied"
    //     });
    //   }

    const results = await db.query('SELECT * FROM product WHERE category=$1 LIMIT $2',[req.product.category,limit]);
    return res.status(200).json({
        status: "Success",
        results: results.rows.length, 
        data: {
            product: results.rows,
        },
    });
  }catch(err){
      console.log(err);
  }

});



// LIST PRODUCT CATEGORIES
app.get("/products/categories",async (req,res) => {
  // res.send("hi");
  try{

    // GRAB ALL THE REQUEST PARAMETERS
    // let limit = req.query.limit ? parseInt(req.query.limit) : 6;




    // WE ALSO NEED TO SEE IF USER IS AUTHENTICATED
    // var id = req.params.userId;
  
    // const results1 = await db.query('SELECT * FROM users WHERE id=$1',[id]);

    // if(!results1){
    //   return res.status(400).json({
    //     "err" : "User with that id does not found"
    //   });
    // }  

    // req.profile = results1.rows[0];
    // TO SEE IF USER IS ADMIN
    // ADMIN IS ONE AND SAMPLE USER IS 0
    // if(req.profile.role === 0){
    //   return res.status(403).json({
    //     error: "Admin resource! Access denied"
    //   });
    // }

    // TO SEE IF USER HAS AUTHENTICATION
    // let user = req.profile && req.auth && req.profile.id === req.auth.id;
    //   if(!user){
    //     return res.status(403).json({
    //       error: "Access denied"
    //     });
    //   }

    const results = await db.query('SELECT DISTINCT category FROM product');
    return res.status(200).json({
        status: "Success",
        results: results.rows.length, 
        data: {
            product: results.rows,
        },
    });
  }catch(err){
      console.log(err);
  }

});





// LIST PRODUCT BY SEARCH
app.post("/products/by/search",async (req,res) => {
  // res.send("hi");
  try{

    // GRAB ALL THE REQUEST PARAMETERS
    // let limit = req.query.limit ? parseInt(req.query.limit) : 6;

    let order = req.body.order ? req.body.order : "desc";
    let sortBy = req.body.sortBy ? req.body.sortBy : "id";
    let limit = req.body.limit ? parseInt(req.body.limit) : 100;
    let skip = parseInt(req.body.skip);
    let greaterThan;
    let lessThan;


    // WE ALSO NEED TO SEE IF USER IS AUTHENTICATED
    // var id = req.params.userId;
  
    // const results1 = await db.query('SELECT * FROM users WHERE id=$1',[id]);

    // if(!results1){
    //   return res.status(400).json({
    //     "err" : "User with that id does not found"
    //   });
    // }  

    // req.profile = results1.rows[0];
    // TO SEE IF USER IS ADMIN
    // ADMIN IS ONE AND SAMPLE USER IS 0
    // if(req.profile.role === 0){
    //   return res.status(403).json({
    //     error: "Admin resource! Access denied"
    //   });
    // }

    // TO SEE IF USER HAS AUTHENTICATION
    // let user = req.profile && req.auth && req.profile.id === req.auth.id;
    //   if(!user){
    //     return res.status(403).json({
    //       error: "Access denied"
    //     });
    //   }

      for (let key in req.body.filters) {
        if (req.body.filters[key].length > 0) {
            if (key === "price") {
                // gte -  greater than price [0-10]
                // lte - less than
                
                greaterThan = req.body.filters[key][0];
                lessThan = req.body.filters[key][1];
              
            } else {
              greaterThan = req.body.filters[key];
              lessThan = req.body.filters[key];
            }
        }
    }


    const results = await db.query('SELECT * FROM product WHERE price BETWEEN $1 AND $2 ORDER BY '+ sortBy + ' ' + order +' LIMIT $3',[lessThan,greaterThan,limit]);
    return res.status(200).json({
        status: "Success",
        results: results.rows.length, 
        data: {
            product: results.rows,
        },
    });
  }catch(err){
      console.log(err);
  }

});


// USER PROFILE READ
app.get("/user/:userId",requireSignin,isAuth,async (req,res) => {
  // res.send("hi");
  try{
    req.profile.password = undefined;
    return res.status(200).json({
        status: "Success",
        data: {
            user: req.profile,
        },
      });
  }catch(error){
    console.log(error);
  }  
  
});


// USER PROFILE UPDATE
app.put("/user/:userId",requireSignin,isAuth,async (req,res) => {
  // res.send("hi");
  try{
      if(!req.body.name ||!req.body.email || !req.body.about){
        return res.status(400).json("Invalid form submission");
      }      

      let id = req.profile.id;
      const users = await db.query('update users SET name=$1, email=$2, about=$3 where id=$4 returning *',[req.body.name,req.body.email,req.body.about,id]);
      return res.status(200).json({
        status: "Success",
        results: users.rows.length, 
        data: {
            users: users.rows,
        },
    });
  }catch(error){
    console.log(error);
  }
  
});








const port = process.env.PORT || 8000;

app.listen(port,()=>{
    console.log(`App is running on port ${port}`);
});
