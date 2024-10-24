const express=require("express");
const mongoose=require("mongoose");
const bcrypt=require("bcryptjs");
const jwt=require("jsonwebtoken");
// Data Base Connection
mongoose.connect("mongodb://localhost:27017/auth-demo")
.then(() =>{
    console.log("Database Connected")
})
.catch((err)=>{
    console.log(err)
})
//schema for users
const userSchema=mongoose.Schema({
    name:{
        type:String,
        required:true
    },
    email:{
        type:String,
        required:true
    },
    password:{
        type:String,
        required:true
    }
},{timestamps:true})

// model for user
const userModel = mongoose.model("users",userSchema)

//End points

const app = express();
app.use(express.json())

app.post("/register",(req,res)=>{
    let user=req.body;
    bcrypt.genSalt(10,(err,salt)=>{
        if (!err)
        {
            bcrypt.hash(user.password,salt,(err,hpass)=>{
                if (!err)
                {
                    user.password=hpass;
                    userModel.create(user)
                    .then((doc)=>{
                        res.status(201).send({message:"User Registartion Successful"})
                    })
                    .catch((err)=>{
                        console.log(err);
                        res.status(500).send({message:"some problem"})
                    })
                }

            })
        }
    })    
})
// End point for Login

app.post("/login",(req,res)=>{
    let userCredential=req.body;
    userModel.findOne({email:userCredential.email})
    .then((user)=>{
        if (user!==null)
        {
            bcrypt.compare(userCredential.password,user.password,(err,result)=>{
                if (result==true)
                {
                    jwt.sign({email:userCredential.email},"seckey",(err,token)=>{
                        if (!err)
                        {
                            res.send({token:token})
                        }
                        else
                        {
                            res.status(500).send({message:"some issue while creating the token please try again"})
                        }
                    })
                }
                else
                {
                    res.status(401).send({message:"Incorrect Password"})
                }
            })           
        }
        else
        {
            res.status(404).send({message:"User Not Exist"})
        }       
    })
    .catch((err)=>{
        res.send({message:"SOME PROBLEM"})
    })
})


app.get("/getdata",verifyToken,(req,res)=>{

    res.status(201).send("USER SUCCESSFULLY REACHED EXPECTED API PAGE");
})

function verifyToken(req,res,next)
{
    let token=req.headers.authorization.split(" ")[1];
    jwt.verify(token,"seckey",(err,data)=>{
        if (!err)
        {
            console.log(data)
            next();
        }
        else
        {
            res.status(401).send({message:"Invalid token,please login again"})
        }
    })
    
}    
//  
app.listen(8000,()=>{
    console.log("Server Started");
})