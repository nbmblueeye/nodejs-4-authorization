const http = require('http');
const url = require("url");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const port = 3000;

const saltRound = 10;
const secretKey = "12345";
const sampleAccessToken = [];

let users = [
    { id: 1, email: 'user1@gmail.com', password: bcrypt.hashSync("user1", saltRound), role: "admin" },
    { id: 2, email: 'user2@gmail.com', password: bcrypt.hashSync("user2", saltRound), role: "user" },
    { id: 3, email: 'user3@gmail.com', password: bcrypt.hashSync("user3", saltRound), role: "user" },
    { id: 4, email: 'user4@gmail.com', password: bcrypt.hashSync("user4", saltRound), role: "user" },
    { id: 5, email: 'user5@gmail.com', password: bcrypt.hashSync("user5", saltRound), role: "user" },
    { id: 6, email: 'user6@gmail.com', password: bcrypt.hashSync("user6", saltRound), role: "user" },
    { id: 7, email: 'user7@gmail.com', password: bcrypt.hashSync("user7", saltRound), role: "user" },
    { id: 8, email: 'user8@gmail.com', password: bcrypt.hashSync("user8", saltRound), role: "user" },
    { id: 9, email: 'user9@gmail.com', password: bcrypt.hashSync("user9", saltRound), role: "user" },
    { id: 10, email: 'user10@gmail.com', password: bcrypt.hashSync("user10", saltRound), role: "user" },
    { id: 11, email: 'user11@gmail.com', password: bcrypt.hashSync("user11", saltRound), role: "user" },
    { id: 12, email: 'user12@gmail.com', password: bcrypt.hashSync("user12", saltRound), role: "user" },
    { id: 13, email: 'user13@gmail.com', password: bcrypt.hashSync("user13", saltRound), role: "user" },
    { id: 14, email: 'user14@gmail.com', password: bcrypt.hashSync("user14", saltRound), role: "user" },
    { id: 15, email: 'user15@gmail.com', password: bcrypt.hashSync("user15", saltRound), role: "user" },
];



const hashPassword = async(password) => {
    return await bcrypt.hash(password, saltRound);
}

const comparedPassword = async(password, hashedPassword) => {
    return await bcrypt.compare(password, hashedPassword);
}

const generateAccessToken = (email, role) => {
    return jwt.sign({email, role}, secretKey, { expiresIn: '30m'});
};

const generateRefreshToken = (email, role) => {
    return jwt.sign({email, role}, secretKey, { expiresIn: '7d'});
};

const register = (req, res) => {
    let body = "";
    req.on("data", (chunk) => {
        body += chunk.toString();
    });

    req.on("end", async() => {

        let newUser = JSON.parse(body);
        const { email, password } = newUser;
        if(!email){
            res.writeHead(400, {
                "Content-Type": "Text/plain",
            });
            res.end("Email is required");
            return false;
        }else if(email && users.find(user => user.email === email)){
            res.writeHead(400, {
                "Content-Type": "Text/plain",
            });
            res.end("Email is already existed");
            return false;
        };

        if(!password){
            res.writeHead(400, {
                "Content-Type": "Text/plain",
            });
            res.end("Password is required");
            return false;
        };

        newUser = {id: users.length + 1, email, password, role:"user"};
        newUser.password = await hashPassword(password);
        users.push(newUser);

        let cloneUser = {...newUser};
        delete cloneUser.password;

        res.writeHead(200, {
            "Content-Type": "application/json",
        });
        res.end(JSON.stringify({
            message: "Register success",
            data: cloneUser,
        }));
    })
}

const login = (req, res) => {
    let body = "";
    req.on("data", (chunk) => {
        body += chunk.toString();
    });

    req.on("end", async() => {
        const { email, password} = JSON.parse(body);
        if(!email){
            res.writeHead(400, {
                "Content-Type": "Text/plain",
            });
            res.end("Email is required");
            return false;
        }

        if(!password){
            res.writeHead(400, {
                "Content-Type": "Text/plain",
            });
            res.end("Password is required");
            return false;
        };

        const checkExistedUser = users.find(user => user.email === email);
        if(!checkExistedUser){
            res.writeHead(404, {
                "Content-Type": "Text/plain",
            });
            res.end("User does not exist");
            return false;
        }else{
            let checkPassword = await comparedPassword(password, checkExistedUser.password);
            if(checkPassword){
                const accessToken = generateAccessToken(checkExistedUser.email, checkExistedUser.role);
                const refreshToken = generateRefreshToken(checkExistedUser.email, checkExistedUser.role);
                sampleAccessToken.push(accessToken);
                const cloneUser = {...checkExistedUser};
                delete cloneUser.password;

                res.writeHead(200, {
                    "Content-Type": "application/json",
                });
                res.end(JSON.stringify({
                    message: "Login success",
                    data: cloneUser,
                    accessToken,
                    refreshToken
                }));
            }
        }

    })
}

//Authentication Admin
//3 Api GET 

//Check if the user is Admin
const checkUserIsAdmin = (req, res) => {
    const authorizedHeader = req.headers.authorization;
    if(!authorizedHeader || !authorizedHeader.startsWith("Bearer ")){
        res.writeHead(401, {
            "Content-Type": "text/plain",
        });
        res.end("Unauthorized");
        return false;
    }
    const accessToken = authorizedHeader.split(" ")[1];
    if(!accessToken || !sampleAccessToken.includes(accessToken) ) {
        res.writeHead(401, {
            "Content-Type": "Text/plain",
        });
        res.end("Unauthorized Token");
        return false;
    }

    return jwt.verify(accessToken, secretKey, (error, decodedToken) => {
                if(error){
                    res.writeHead(401, {
                        "Content-Type": "Text/plain",
                    });
                    res.end("Unverified Token");
                    return false;
                }
                const { role } = decodedToken;
                if(role !== "admin"){
                    res.writeHead(403, {
                        "Content-Type": "Text/plain",
                    });
                    res.end("Forbidden User");
                    return false;
                }else{
                    return role;
                }
        
    })
}

//Get All Users
const handleApiGetListUser = (req, res) => {
    
    const isAdmin = checkUserIsAdmin(req, res);
    if(isAdmin){
        let cloneUsers = users.map(user => {
            let cloneUser = {...user};
            delete cloneUser.password;
            return cloneUser;
        });

        res.writeHead(200, {
            "Content-Type": "application/json",
        });
        res.end(JSON.stringify({
                data: cloneUsers
            })
        );
    }

}

//Get Detail User
const handleApiGetUserDetail = (req, res) => {
    const isAdmin = checkUserIsAdmin(req, res);
    if(isAdmin){
        let pathUrl = url.parse(req.url, true);
        let userId = pathUrl.pathname.split("/")[4];
        const findUser = users.find(user => user.id === parseInt(userId));
        if(!findUser) {
            res.writeHead(400, {
                "Content-Type": "Text/plain",
            });
            res.end("User not found");
            return false;
        }

        let cloneUser = {...findUser};
        delete cloneUser.password
        res.writeHead(200, {
            "Content-Type": "application/json",
        });
        res.end(JSON.stringify({
                data: cloneUser
            })
        );
    }
}

//Get User Pagination
const handleApiGetUserPagination = (req, res) => {
    
    const isAdmin = checkUserIsAdmin(req, res);
    if(isAdmin){
        const pathUrl = url.parse(req.url, true);
        const pageIndex = parseInt(pathUrl.query.pageIndex) || 1;
        const limit = parseInt(pathUrl.query.limit) || 10;
        const totalPages = Math.ceil(users.length / limit);

        let startIndex = (pageIndex - 1) * limit;
        let endIndex = (startIndex + limit) - 1;

        let cloneUsers = users.map(user => {
            let cloneUser = {...user};
            delete cloneUser.password;
            return cloneUser;
        });

        let result = {
            data: cloneUsers.slice(startIndex, endIndex + 1),
            currentPage: pageIndex,
            itemsPerPage: limit,
            totalPages: totalPages
        }
        
        res.writeHead(200, {
            "Content-Type": "application/json",
        });
        res.end(JSON.stringify(result));
    }
}

//admin
//call api -> add key class
const handleApiAddClassForUser = (req, res) => {
    let body = "";
    req.on("data", (chunk) => {
        body += chunk.toString();
    });
    req.on("end", () => {
        let { email } = JSON.parse(body);
        const userIndex = users.findIndex(user => user.email === email);
        if( userIndex === -1) {
            res.writeHead(404, {
                "Content-Type": "Text/plain",
            });
            res.end("User does not exist");
            return false;
        }

        const isAdmin = checkUserIsAdmin(req, res);
        if(isAdmin){
            users[userIndex] = {...users[userIndex], class: `class${users[userIndex].id}-1`};
            let cloneUsers = users.map(user => {
                let cloneUser = {...user};
                delete cloneUser.password;
                return cloneUser;
            });
            res.writeHead(200, {
                "Content-Type": "application/json",
            });
            res.end(JSON.stringify(cloneUsers));
        }
    });
}

//admin
//call api -> update key class
const handleApiUpdateClassForUser = (req, res) => {
    let body = "";
    req.on("data", (chunk) => {
        body += chunk.toString();
    });
    
    req.on("end", () => {
        let { email } = JSON.parse(body);
        const userIndex = users.findIndex(user => user.email === email);
        if(userIndex === -1) {
            res.writeHead(404, {
                "Content-Type": "Text/plain",
            });
            res.end("User does not exist");
            return false;
        }

        const isAdmin = checkUserIsAdmin(req, res);
        if( isAdmin ){
            let currentUser = users[userIndex];
            users[userIndex] = {...currentUser, class: "class" in currentUser ? 
            `class${currentUser.id}-${parseInt(currentUser.class.split("-")[1]) + 1}`
            :
            `class${currentUser.id}-1`}
          
            let cloneUsers = users.map(user => {
                let cloneUser = {...user};
                delete cloneUser.password;
                return cloneUser;
            });
            res.writeHead(200, {
                "Content-Type": "application/json",
            });
            res.end(JSON.stringify(cloneUsers));
        }
    })        
}

//admin
//call api -> delete key class
const handleApiDeleteClassForUser = (req, res) => {
    let body = "";
    req.on("data", (chunk) => {
        body += chunk.toString();
    });
    
    req.on("end", () => {
        let { email } = JSON.parse(body);
        const userIndex = users.findIndex(user => user.email === email);
        if(userIndex === -1) {
            res.writeHead(404, {
                "Content-Type": "Text/plain",
            });
            res.end("User does not exist");
            return false;
        }

        const isAdmin = checkUserIsAdmin(req, res);
        if( isAdmin ){
            users[userIndex] = {...users[userIndex]}
            if("class" in users[userIndex]){
                delete users[userIndex].class;
            }

            let cloneUsers = users.map(user => {
                let cloneUser = {...user};
                delete cloneUser.password;
                return cloneUser;
            });
            res.writeHead(200, {
                "Content-Type": "application/json",
            });
            res.end(JSON.stringify(cloneUsers));
        }
    })        
}


const server = http.createServer(async (req, res) => {
    let pathUrl = url.parse(req.url, true);
    let userId = pathUrl.pathname.split("/")[4];
    
    if(req.method === 'POST' && pathUrl.pathname === "/api/auth/register") {
        register(req, res);
    }else if(req.method === 'POST' && pathUrl.pathname === "/api/auth/login") {
        login(req, res);
    }else if(req.method === 'GET' && pathUrl.pathname === "/api/auth/users") {
        handleApiGetListUser(req, res);
    }else if(req.method === 'GET' && pathUrl.pathname.startsWith("/api/auth/user") + userId) {
        handleApiGetUserDetail(req, res);
    }else if(req.method === 'GET' && pathUrl.pathname.startsWith("/api/auth/pagination")) {
        handleApiGetUserPagination(req, res);
    }else if(req.method === 'POST' && pathUrl.pathname === "/api/auth/users/add-class" ) {
        handleApiAddClassForUser(req, res);
    }else if(req.method === 'PUT' && pathUrl.pathname === "/api/auth/users/update-class" ) {
        handleApiUpdateClassForUser(req, res);
    }else if(req.method === 'DELETE' && pathUrl.pathname === "/api/auth/users/delete-class" ) {
        handleApiDeleteClassForUser(req, res);
    }else{
        res.writeHead(400, {
            "Content-Type": "Text/plain",
        });
        res.end("Route not found");
        return false;
    }

});

server.listen( port, async () => {
    console.log("Server is running on port " + port);
})
  