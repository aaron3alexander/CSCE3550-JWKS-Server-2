const express = require("express");
const jwt = require("jsonwebtoken");
const jose = require("node-jose");
const sqlite3 = require("sqlite3").verbose();
const pemJwk = require("pem-jwk");
const app = express();
const port = 8080;

let keyPair;
let expiredKeyPair;
let token;

let db;
function startDB() {
  //function that connects to the database and initalizes it as empty
  db = new sqlite3.Database("totally_not_my_privateKeys.db");
  db.run(`
    CREATE TABLE IF NOT EXISTS keys(
      kid INTEGER PRIMARY KEY AUTOINCREMENT,
      key BLOB NOT NULL,
      exp INTEGER NOT NULL
    )
  `);
}

async function generateKeyPairs() {
  //function that creates both a normal key and an expired key and stores it in the database
  keyPair = await jose.JWK.createKey("RSA", 2048, {
    alg: "RS256",
    use: "sig",
  });
  const goodExpiry = Math.floor(new Date().getTime() / 1000) + 3600; //expires 1 hour in the future

  expiredKeyPair = await jose.JWK.createKey("RSA", 2048, {
    alg: "RS256",
    use: "sig",
  });
  const badExpiry = Math.floor(new Date().getTime() / 1000) - 3600; //expired 1 hour in the past

  db.run("INSERT INTO keys (key, exp) VALUES (?, ?)", [
    keyPair.toPEM(true), //converting to PEM format here so that it will insert into database
    goodExpiry,
  ]);

  db.run("INSERT INTO keys (key, exp) VALUES (?, ?)", [
    expiredKeyPair.toPEM(true), //converting to PEM format here so that it will insert into database
    badExpiry,
  ]);
}

function generateToken() {
  //generates a JWT token
  const payload = {
    user: "sampleUser",
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
  };
  const options = {
    algorithm: "RS256",
    header: {
      typ: "JWT",
      alg: "RS256",
      kid: keyPair.kid,
    },
  };

  token = jwt.sign(payload, keyPair.toPEM(true), options);
}

function generateExpiredToken() {
  //generates an expired JWT token
  const payload = {
    user: "sampleUser",
    iat: Math.floor(Date.now() / 1000) - 30000,
    exp: Math.floor(Date.now() / 1000) - 3600, //expired already
  };
  const options = {
    algorithm: "RS256",
    header: {
      typ: "JWT",
      alg: "RS256",
      kid: expiredKeyPair.kid,
    },
  };

  expiredToken = jwt.sign(payload, expiredKeyPair.toPEM(true), options);
}

app.all("/auth", (req, res, next) => {
  if (req.method !== "POST") {
    return res.status(405).send("Method Not Allowed");
  }
  next();
});

// Middleware to ensure only GET requests are allowed for /jwks - came from Jacob's code
app.all("/.well-known/jwks.json", (req, res, next) => {
  if (req.method !== "GET") {
    return res.status(405).send("Method Not Allowed");
  }
  next();
});

app.get("/.well-known/jwks.json", async (req, res) => {
  const query = "SELECT * FROM keys WHERE exp >= ?"; //query I'm using for the database
  db.all(query, [Math.floor(Date.now() / 1000)], async (err, rows) => {
    //query the db
    if (err) {
      console.error(err);
      return res.status(500).send("Internal Server Error");
    }

    try {
      //promise to await the database stuff
      const keyPromises = rows.map(async (row) => {
        const key = await jose.JWK.asKey({
          //create a jwk
          kid: String(row.kid),
          alg: "RS256",
          kty: "RSA",
          use: "sig",
          n: pemJwk.pem2jwk(row.key).n, //translate from pem format, grab modulus
          e: "AQAB",
        });
        return key.toJSON();
      });

      const validKeys = await Promise.all(keyPromises);
      const jwksResponse = {
        keys: validKeys,
      };
      res.setHeader("Content-Type", "application/json");
      res.json(jwksResponse);
    } catch (error) {
      console.error(error);
      res.status(500).send("Server Error");
    }
  });
});

app.post("/auth", (req, res) => {
  const isExpired = req.query?.expired === "true"; //bool to check if expired param is passed in
  const dbQuery = isExpired
    ? "SELECT * FROM keys WHERE exp < ?"
    : "SELECT * FROM keys WHERE exp >= ?"; //change db query based on isExpired bool

  db.get(dbQuery, [Math.floor(Date.now() / 1000)], (err, row) => {
    if (err) {
      console.error(err);
      return res.status(500).send("Server Error");
    }
    if (!row) {
      return res.status(404).send("Key not found");
    }

    const options = {
      algorithm: "RS256",
      header: {
        typ: "JWT",
        alg: "RS256",
        kid: String(row.kid),
      },
    };

    const payload = {
      user: "sampleUser",
      iat: Math.floor(Date.now() / 1000),
      exp: row.exp,
    };

    const token = jwt.sign(payload, row.key, options); //sign a jwt with the private key
    res.send(token);
  });
});

startDB(); //initialize database

generateKeyPairs().then(() => {
  generateToken();
  generateExpiredToken();
  app.listen(port, () => {
    console.log(`Server started on http://localhost:${port}`);
  });
});

module.exports = app; //export for testing
