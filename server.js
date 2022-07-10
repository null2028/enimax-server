require('dotenv').config();
var express = require('express');
var cookieParser = require('cookie-parser');
const xss = require("xss");
const bcrypt = require('bcrypt');
var session = require('express-session');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const redis = require('redis');
const multer = require('multer');
const upload = multer();
var https = require('http');
const bodyParser = require('body-parser');
const RedisStoreLimit = require("rate-limit-redis");

let RedisStore = require('connect-redis')(session);
let redisClient = redis.createClient({
    legacyMode: true
});


const saltRounds = 10;
async function config(){
    await redisClient.connect();
    
}

const cookieExpirationDate = new Date();
const cookieExpirationDays = 30;
cookieExpirationDate.setDate(cookieExpirationDate.getDate() + cookieExpirationDays);


config();

const dbFile = "./.data/vid.db";
const exists = fs.existsSync(dbFile);
const sqlite3 = require("sqlite3").verbose();
const db = new sqlite3.Database(dbFile);


db.serialize(() => {
    if (!exists) {
        db.run("CREATE TABLE `playlist` (`id` INTEGER PRIMARY KEY,`room_name` text NOT NULL,`username` text NOT NULL, `misc` int DEFAULT NULL )");

        db.run("CREATE TABLE `playlistOrder` (`order1` text NOT NULL,`misc` text,`username` text PRIMARY KEY NOT NULL )");
        db.run(" CREATE TABLE `users` (`id` INTEGER PRIMARY KEY ,`username` varchar(20) UNIQUE NOT NULL, `hashed_password` blob NOT NULL,`salt` blob NULL,`email` text NOT NULL,`reset` text,`timestamp` BIGINT DEFAULT NULL  )");

        db.run("CREATE UNIQUE INDEX video_idx_username ON users (username)");
        db.run("CREATE TABLE `video` (`id` INTEGER PRIMARY KEY,`cur_time` float(12,3) NOT NULL,`ep` float(12,3) NOT NULL,`name` text NOT NULL,`time1` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,`time2` int DEFAULT NULL,`image` text,`curlink` text,`username` text NOT NULL,`comp` int NOT NULL DEFAULT '0',`main_link` text,`times` int NOT NULL DEFAULT '0' );")
            
        db.run("CREATE INDEX video_idx_name ON video (name)");  
    }
  });



const loginLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute

    max: 10,
    message: "{\"status\": 400, \"message\":\"Too many requests\"}",
    store: new RedisStoreLimit({
        client: redisClient,
    }),
    standardHeaders: true,
    legacyHeaders: false,
});


const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 24 * 1000, // 24 hours
    max: 1,
 
    message: "{\"status\": 400, \"message\":\"Too many requests\"}",
    store: new RedisStoreLimit({
        client: redisClient,
    }),
    standardHeaders: true,
    skipFailedRequests: true,
    legacyHeaders: false,
});



const resetLimiter = rateLimit({
    windowMs: 60 * 1000 * 5, // 5 minute
    max: 5,
    store: new RedisStoreLimit({
        client: redisClient,
    }),
    message: "{\"status\": 400, \"message\":\"Too many requests\"}",
    standardHeaders: true,
    legacyHeaders: false,
});

function goodRequest(data, keys) {
    for (var i = 0; i < keys.length; i++) {
        if (!(keys[i] in data)) {
            return false;
        }
    }

    return true;
}


redisClient.on("error", function(error) {
    console.error(error);
});


var app = express();

var jsonParser = bodyParser.json();
var urlencodedParser = bodyParser.urlencoded({ extended: true });

app.use(upload.none());
app.use(jsonParser);
app.use(urlencodedParser);

app.use(cookieParser());


app.use(function(req, res, next) {
    try {
        if (!("cookie" in req.headers)){
        req.headers["cookie"] = req.headers["x-session"];
        }
    } catch (err) {

    }
    next();
});

app.use(function(req, res, next) {
    res.header('Access-Control-Allow-Origin', "*");
    res.header("Access-Control-Allow-Headers", "Access-Control-Allow-Headers, Origin,Accept, X-Requested-With, Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers");
    next();
});

app.use(session({
    secret: process.env.secret,
    resave: false,
    saveUninitialized: false,
    store: new RedisStore({ client: redisClient }),
    cookie: {
        httpOnly: false,
        expires: cookieExpirationDate
    },
}));


function updateSession(sessionId, username) {
    return (new Promise(function(resolve, reject) {
        redisClient.HLEN(username, function(err, res) {
            if (err) {
                reject(err);
            } else {
                if (res >= 10) {
                    redisClient.hkeys(username, function(err, res) {
                        if (err) {
                            reject(err);
                        } else {
                            redisClient.HDEL([username, ...res.slice(0, res.length - 10)], function(err, res) {

                            });

                            redisClient.HSET(username,[sessionId, 0], function(err, res) {
                                if (err) {
                                    reject(err);
                                } else {
                                    resolve();
                                }
                            });
                        }
                    });

                } else {
                    redisClient.HSET(username,[sessionId, 0], function(err, res) {
                        if (err) {
                            reject(err);
                        } else {
                            resolve();
                        }
                    });
                }


            }

        });
    }));

}

function revokeAllSessions(sessionId, username) {


    return (new Promise(function(resolve, reject) {
        let out = redisClient.DEL(username, function(err, res) {
            if (err) {
                reject(err);
            } else {

                resolve(res);
            }
        });


    }));

}

function checkIfValid(req) {

    return (new Promise(function(resolve, reject) {
        try {
            if ("session" in req && "user" in req["session"]) {
                let out = redisClient.HEXISTS([req.session.user.username, req.session.id], function(err, res) {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(res);
                    }
                });
            } else {
                reject("bad reqq");
            }
        } catch (err) {
            reject(err);
        }
    }));
}

function deleteSession(sessionId, username) {


    return (new Promise(function(resolve, reject) {
        let out = redisClient.HDEL([username, sessionId], function(err, res) {
            if (err) {
                reject(err);
            } else {

                resolve(res);
            }
        });
    }));
}


app.use('/login', loginLimiter);
app.post('/login', function(req, res) {

    if (goodRequest(req.body, ["username", "password"])) {

        let username = req.body.username;
        let password = req.body.password;
        db.all('SELECT * FROM users WHERE username = ?', [username], function(err, row) {

            if (err) {
                res.status(500).json({ "status": 500, "message": "Internal Error", "errorCode": 60000 });

                return;
            } else if (row.length == 0) {
                res.status(400).json({ "status": 400, "message": "Incorrect username or password", "errorCode": 60001 });

                return;
            } else {


                bcrypt.compare(password, row[0].hashed_password, async function(err, result) {
                    if(err){
                        res.status(500).json({ "status": 500, "message": "Internal Error", "errorCode": 60002 });
                        return;
                    }else if(result === false){
                        res.status(400).json({ "status": 400, "message": "Incorrect username or password", "errorCode": 60001 });
                        return;
                    }else if(result === true){
                        let user = {
                            id: row[0].id.toString(),
                            username: row[0].username,
                        };
    
                        try {
                            if ("user" in req.session) {
                                await deleteSession(req.session.id, req.session.user.username);
                            }
    
                            await updateSession(req.session.id, user.username);
                            req.session["user"] = user;
                            res.status(200).json({ "status": 200, "message": "success", "errorCode": 60005 });
    
                        } catch (err) {
                            console.log(err);
                            res.status(500).json({ "status": 500, "message": "Unexpected error", "errorCode": 60004 });
    
                        }
                    }
                });
                
            }
        });
    } else {
        res.status(400).json({ "status": 400, "message": "Bad Request", "errorCode": 60006 });
        return;
    }
});


app.use('/register', registerLimiter);

app.post('/register', function(req, res) {
    if (goodRequest(req.body, ["email", "username", "password"])) {
        try {
            let email = req.body.email;
            let username = req.body.username;
            let password = req.body.password;



            bcrypt.genSalt(saltRounds, function(err, salt) {
                if(err){
                    res.status(500).json({ "status": 500, "message": "Internal Error", "errorCode": 10001 });
                    return;
                }
                bcrypt.hash(password, salt, function(err, hash) {
                    if(err){
                        res.status(500).json({ "status": 500, "message": "Internal Error", "errorCode": 10002 });
                        return;
                    }


                    mysql_query('INSERT INTO users (username, hashed_password, email) VALUES (?, ?, ?)',[
                        username,
                        hash,
                        email,
                    ]).then(function(){
                        res.status(200).json({ "status": 200, "message": "Done!" });
    
                    }).catch(function(){
                        res.status(500).json({ "status": 500, "message": "Internal Error", "errorCode": 10004 });
    
                    });

                });
            });
        } catch (err) {
            console.log(err);
            res.status(500).json({ "status": 500, "message": "Internal Error", "errorCode": 10003 });

            return;
        }
    } else {
        res.status(400).json({ "status": 400, "message": "Bad request", "errorCode": 10000 });
        return;
    }
});





app.post('/logout', async function(req, res) {
    try {
        let check = await checkIfValid(req);
        if (check == 1) {
            try {
                let result = await deleteSession(req.session.id, req.session.user.username);
                req.session.destroy();

                if (result == 0) {
                    res.status(200).json({ "status": 200, "message": "Already logged out" });
                } else {
                    res.status(200).json({ "status": 200, "message": "Logged out" });
                }
            } catch (err) {
                res.status(500).json({ "status": 500, "message": "Unexpected Error", "errorCode": 30000 });
            }
        } else {
            res.status(400).json({ "status": 400, "message": "Session expired", "errorCode": 30002 });
        }
    } catch (err) {
        res.status(500).json({ "status": 500, "message": "Unexpected Error", "errorCode": 30001 });
    }

});


app.use('/reset', resetLimiter);

app.post('/reset', async function (req, res) {

  if (goodRequest(req.body, ["oldPassword", "newPassword"])) {
    try {
      let check = await checkIfValid(req);
      if (check == 1) {
        let oldPassword = req.body.oldPassword;
        let newPassword = req.body.newPassword;
        db.all('SELECT * FROM users WHERE username = ?', [req.session.user.username], function (err, row) {
          if (err) {
            res.status(500).json({ "status": 500, "message": "Unexpected Error", "errorCode": 40000 });
            return;
          }
          else if (row.length == 0) {
            res.status(500).json({ "status": 500, "message": "Unexpected Error", "errorCode": 40001 });
            return;
          }
           else {

            bcrypt.compare(oldPassword, row[0].hashed_password, function(err, result) {
                if (err) {
                    res.status(500).json({ "status": 500, "message": "Unexpected Error", "errorCode": 40005 });
                    return;
    
                  }
                  else if (result === false) {
                    res.status(500).json({ "status": 500, "message": "The entered password doesn't match your old password.", "errorCode": 40006 });
                    return;
                  }
                  else if (result === true) {


                  
                    bcrypt.genSalt(saltRounds, function(err, salt) {
                        if(err){
                            res.status(500).json({ "status": 500, "message": "Internal Error", "errorCode": 40007 });
                            return;
                        }
                        bcrypt.hash(newPassword, salt, function(err, hash) {
                            if(err){
                                res.status(500).json({ "status": 500, "message": "Internal Error", "errorCode": 40008 });
                                return;
                            }
                            

                            db.all('UPDATE users SET hashed_password=?, reset=?, timestamp=? WHERE username =?', [hash, "0", 0, req.session.user.username], async function (err, row) {
                                if (err) {
                                    res.status(500).json({ "status": 500, "message": "Unexpected Error", "errorCode": 40010 });
                                    return;
                                }
                                else {
                                    try {
                                        await revokeAllSessions(req.session.id, req.session.user.username);
                                        res.status(200).json({ "status": 200, "message": "Your password has been changed"});


                                    } catch (err) {
                                        res.status(500).json({ "status": 500, "message": "Something went wrong; although, your password has been changed, but the other sessions are still active.", "errorCode": 40010 });

                                    }
                                }
                            });
        
                              
                        });
                    });


                  }
            });
          }
        });
      } else {
        res.status(400).json({ "status": 400, "message": "Your session has expired", "errorCode": 40011 });

      }
    } catch (err) {
        console.log(err);
      res.status(500).json({ "status": 500, "message": "Unexpected Error", "errorCode": 40012 });

    }
  } else {
    res.status(400).json({ "status": 400, "message": "Bad/Incomplete request", "errorCode": 40013 });

  }

});

async function mysql_query(command, inputs, lastID = false) {

    return new Promise(function(resolve, reject) {
        try {
            if(lastID){
                db.run(command,inputs,function(error){
                    if(error){
                        reject("Internal error.");

                    }else{
                        resolve(this);

                    }
                });

            }else{
                db.all(command,inputs,function(error, result){
                    if(error){
                        reject("Internal error.");

                    }else{
                        resolve(result);

                    }
                });
            }
        } catch (error) {
            reject(error);

        }


    });


}

function timern() {
    return parseInt((new Date()).getTime() / 1000);
}

async function updateTime(req) {
    try {

        if ("time" in req.body && "name" in req.body && "ep" in req.body) {
            var cur = req.body.time;
            var name = req.body.name;
            var ep = parseFloat(req.body.ep);
            var username = req.session.user.username;



            var getcount = await mysql_query("SELECT count(*) as count from video where ep=? and name=? and username=?", [ep, name, username]);

            if (getcount[0].count >= 1) {

                var update = await mysql_query("UPDATE video set cur_time=?,time2=?, times=times+1 where ep=? and name=? and username=?", [cur, timern(), ep, name, username]);

                var update = await mysql_query("UPDATE video set time2=? where ep=0 and name=?  and username=?", [timern(), name, username]);




            } else {

                var insert = await mysql_query("INSERT INTO video (ep,cur_time,name,time2,username) VALUES (?,?,?,?,?)", [ep, cur, name, timern(), username]);




            }


            return { "status": 200, "message": "done" };



        } else {
            return { "status": 400, "message": "Bad request" };


        }

    } catch (error) {
        return { "status": 500, "errorCode": 10000, "message": "Database error." };
    }






}


async function getShowInfo(req) {
    try {

        if ("cur" in req.body && "name" in req.body && "ep" in req.body) {
            var cur = req.body.cur;
            var name = req.body.name;
            var nameUm;
            if ("nameUm" in req.body) {
                nameUm = req.body.nameUm;
            } else {
                nameUm = req.body.name;

            }

            var ep = req.body.ep;
            var username = req.session.user.username;

            if (cur.toLowerCase().substring(0, 7) == "?watch=" && cur.toLowerCase().indexOf("javascript") == -1) {



                var response = {};
                var getdata = await mysql_query("SELECT cur_time as current, main_link as mainLink from video where ep=0 and name=? and username=? LIMIT 1", [nameUm, username]);

                if (getdata.length == 0) {


                    await mysql_query("INSERT INTO video (ep,cur_time,name,curlink,time2,username) VALUES (0,?,?,?,?,?)", [ep, nameUm, cur, timern(), username]);



                } else {
                    response.mainLink = getdata[0].mainLink;
                }


                await mysql_query("UPDATE video set cur_time=?,curlink=?,time2=? where name=? and ep=0 and username=?", [ep, cur, timern(), nameUm, username]);





                var getdata = await mysql_query("SELECT cur_time as curtime from video where ep=? and name=? and username=? LIMIT 1", [ep, name, username]);


                if (getdata.length != 0) {
                    response.time = getdata[0].curtime;
                } else {
                    response.time = 0;
                    await mysql_query("INSERT INTO video (ep,cur_time,name,username) VALUES (?,?,?,?)", [ep, 0, name, username]);

                }




                return { "status": 200, "message": "done", "data": response };
            } else {
                return { "status": 400, "message": "You can't use this link" };

            }


        } else {
            return { "status": 400, "message": "Bad request" };


        }

    } catch (error) {
        return { "status": 500, "errorCode": 10000, "message": "Database error." };
    }

}


async function getUserInfo(req) {
    try {

        if (true) {

            var username = req.session.user.username;


            var response = [
                [],
                [],
                []
            ];

            var getData = await mysql_query("SELECT DISTINCT(name) as b,cur_time as a,image,time2,curlink,comp,main_link from video where ep=0  and curlink IS NOT NULL and username=? ORDER BY time2 DESC", [username]);



            if (getData.length > 0) {
                for (var i = 0; i < getData.length; i++) {
                    let temp = [];
                    temp.push(getData[i]["b"], getData[i]["a"], getData[i]["image"], getData[i]["curlink"], getData[i]["comp"], getData[i]["main_link"]);
                    response[0].push(temp);
                }

            }



            var getData = await mysql_query("SELECT id,room_name FROM playlist where username=?", [username]);



            if (getData.length > 0) {
                for (var i = 0; i < getData.length; i++) {

                    response[1].push(getData[i]["room_name"], getData[i]["id"]);
                }

            }


            var getData = await mysql_query("SELECT order1 FROM playlistOrder where username=? LIMIT 1", [username]);



            if (getData.length > 0) {
                for (var i = 0; i < getData.length; i++) {

                    response[2] = [getData[i]["order1"]];
                }

            }



            return { "status": 200, "message": "done", "data": response };



        } else {
            return { "status": 400, "message": "Bad request" };


        }

    } catch (error) {
        console.log(error);
        return { "status": 500, "errorCode": 10000, "message": "Database error." };
    }

}



async function updateImage(req) {
    try {

        if ("img" in req.body && "name" in req.body) {
            var name = req.body.name;
            var img = req.body.img;

            var username = req.session.user.username;

            var main_link = "";

            if ("url" in req.body) {
                main_link = req.body.url;
            }


            var response = {};
            if (img.toLowerCase().indexOf("javascript") == -1 && main_link.toLowerCase().indexOf("javascript") == -1 && main_link.toLowerCase().substring(0, 7) == "?watch=") {

                var getData = await mysql_query("SELECT image from video where ep=0 and name=? and username=? LIMIT 1", [name, username]);

                if (getData.length == 0) {

                    await mysql_query("INSERT INTO video (ep,cur_time,name,image,username,main_link) VALUES (0,1,?,?,?,?)", [name, img, username, main_link]);



                }

                return { "status": 200, "message": "done", "data": response };

            } else {
                return { "status": 400, "message": "You can't use the keyword 'javascript' in the URL." };

            }


        } else {
            return { "status": 400, "message": "Bad request" };


        }

    } catch (error) {
        return { "status": 500, "errorCode": 10000, "message": "Database error." };
    }

}



async function deleteShow(req) {
    try {

        if ("name" in req.body) {

            var name = req.body.name;
            var username = req.session.user.username;

            var response = {};

            await mysql_query("DELETE FROM video where ep=0 and name=? and username=?", [name, username]);



            return { "status": 200, "message": "done", "data": response };



        } else {
            return { "status": 400, "message": "Bad request" };


        }

    } catch (error) {
        return { "status": 500, "errorCode": 10000, "message": "Database error." };
    }

}


async function changeState(req) {
    try {

        if ("state" in req.body && "name" in req.body && !isNaN(parseInt(req.body.state))) {
            var state = parseInt(req.body.state);
            var name = req.body.name;
            var username = req.session.user.username;



            await mysql_query("UPDATE video SET comp=? where ep=0 and name=? and username=?", [state, name, username]);




            var response = {};




            return { "status": 200, "message": "done", "data": response };



        } else {
            return { "status": 400, "message": "Bad request" };


        }

    } catch (error) {
        return { "status": 500, "errorCode": 10000, "message": "Database error." };
    }

}


async function updateImageManual(req) {
    try {

        if ("img" in req.body && "name" in req.body) {
            var img = req.body.img;
            var name = req.body.name;
            var username = req.session.user.username;
            var response = {};

            if (img.toLowerCase().indexOf("javascript") == -1) {

                await mysql_query("UPDATE video set image=? where name=? and ep=0 and username=?", [img, name, username]);

                response.image = img;



                return { "status": 200, "message": "done", "data": response };

            } else {
                return { "status": 400, "message": "You can't have the keyword 'javascript' in the url." };

            }




        } else {
            return { "status": 400, "message": "Bad request" };


        }

    } catch (error) {
        return { "status": 500, "errorCode": 10000, "message": "Database error." };
    }

}


async function addRoom(req) {
    try {

        if ("room" in req.body) {
            var room_name = req.body.room;
            var username = req.session.user.username;

            let getData = await mysql_query("INSERT INTO playlist (room_name,username) VALUES (?,?)", [room_name, username], true);



            var response = {};
            response.lastId = getData.lastID;


            return { "status": 200, "message": "done", "data": response };



        } else {
            return { "status": 400, "message": "Bad request" };


        }

    } catch (error) {
        return { "status": 500, "errorCode": 10000, "message": "Database error." };
    }

}



async function deleteRoom(req) {
    try {

        if ("id" in req.body && !isNaN(parseInt(req.body.id))) {
            var id_room = parseInt(req.body.id);
            var username = req.session.user.username;

            await mysql_query("DELETE FROM playlist where username=? and id=?", [username, id_room]);

            var response = {};




            return { "status": 200, "message": "done", "data": response };



        } else {
            return { "status": 400, "message": "Bad request" };


        }

    } catch (error) {
        return { "status": 500, "errorCode": 10000, "message": "Database error." };
    }

}


async function changeOrder(req) {
    try {

        if ("order" in req.body) {
            var order = req.body.order;
            var username = req.session.user.username;

            order = order.split(",");
            var check = 0;
            for (var i = 0; i < order.length; i++) {
                if (isNaN(parseInt(order[i]))) {
                    check = 1;
                    break;
                }
            }

            var response = {};

            if (check == 0) {

                await mysql_query("INSERT INTO playlistOrder (username,order1) VALUES (?,?) ON CONFLICT(username) DO UPDATE SET order1=?", [username, req.body.order, req.body.order]);



                return { "status": 200, "message": "done", "data": response };

            } else {
                return { "status": 400, "message": "Bad request" };


            }

        } else {
            return { "status": 400, "message": "Bad request" };


        }

    } catch (error) {
        console.log(error);
        return { "status": 500, "errorCode": 10000, "message": "Database error." };
    }

}


async function changeMainLink(req) {
    try {

        if ("url" in req.body && "name" in req.body) {
            var main_link = req.body.url;
            var name = req.body.name;

            var username = req.session.user.username;



            var response = {};
            if (main_link.toLowerCase().indexOf("javascript") == -1 && main_link.toLowerCase().substring(0, 7) == "?watch=") {

                await mysql_query("UPDATE video set main_link=? where name=? and ep=0 and username=?", [main_link, name, username]);


                response.url = main_link;

                return { "status": 200, "message": "done", "data": response };

            } else {
                return { "status": 400, "message": "You can't use the keyword 'javascript' in the URL. Also, you have to start the url with '?watch='" };

            }


        } else {
            return { "status": 400, "message": "Bad request" };


        }

    } catch (error) {
        console.log(error);
        return { "status": 500, "errorCode": 10000, "message": "Database error." };
    }

}
var actions = {
    1: updateTime,
    2: getShowInfo,
    4: getUserInfo,
    5: updateImage,
    6: deleteShow,
    7: changeState,
    9: updateImageManual,
    10: addRoom,
    12: deleteRoom,
    13: changeOrder,
    14: changeMainLink

};


app.use('/api', function(req, res, next) {


    try {



        if ("username" in req.body && "action" in req.body) {
            req.body.action = parseInt(req.body.action);
            next();

        } else {
            res.status(400).json({ "status": 400, "message": "Bad request", "errorCode": 800001 });

        }
    } catch (err) {
        res.status(400).json({ "status": 400, "message": "Unexpected Error" });

    }


});

async function handleRequest(req, res) {



    actions[req.body.action](req).then(function(x) {
        res.json(x);
        res.end();
    }).catch(function(error) {
        res.json(error);
        res.end();
    });

}
app.use('/api', async function(req, res, next) {
    try {
        let check = await checkIfValid(req);
        if (check != 1) {
            res.status(400).json({ "status": 400, "message": "Session expired", "errorCode": 70001 });
        } else {
            next();

        }
    } catch (err) {
        console.log(err);
        res.status(400).json({ "status": 400, "message": "Session expired", "errorCode": 70001 });
    }


});


app.post('/api', (req, res) => {
    try {
        for (value in req.body) {
            if (value == 'username') {
                continue;
            }
            req.body[value] = xss(req.body[value], {
                whiteList: {},
                stripIgnoreTag: false,
            });
        }

        
    } catch (err) {
        console.log(err);
    }

    handleRequest(req, res);
});

var httpsServer = https.createServer({}, app);
var listener = httpsServer.listen(process.env.PORT, () => {
    console.log("Your app is listening on port " + listener.address().port);
  });