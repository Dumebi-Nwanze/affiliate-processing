const express = require("express");
const morgan = require("morgan");
const helmet = require("helmet");
const cors = require("cors");
const axios = require("axios");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const fs = require("fs");
require("dotenv").config();
const bodyParser = require("body-parser");

// const middlewares = require("./middlewares");
// const api = require("./api");
const { log } = require("console");

const app = express();

app.use(morgan("dev"));
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));

const validateToken = (req, res, next) => {
  const authToken = req.headers.authorization;
  if (
    !authToken ||
    authToken !== "Bearer GSDFUGEW76FTGEWILFG3W7L8TW3899H3Q9YH93PORH329E0"
  ) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  next();
};

let authToken = ""; //auth token to be refreshed by setInterval of 10 mins running getToken function

async function getToken() {
  const data = new URLSearchParams();
  data.append("grant_type", "password");
  data.append("username", "developer@glbtrade.co");
  data.append("password", "davidglobal");

  try {
    const response = await axios.post(
      "https://bo-mtrwl.match-trade.com/proxy/auth/oauth/token",
      data,
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization:
            "Basic bGl2ZU10cjFDbGllbnQ6TU9USUI2ckRxbjNDenlNdDV2N2VHVmNhcWZqeDNlNWN1ZmlObG5uVFZHWVkzak5uRDJiWXJQS0JPTGRKMXVCRHpPWURTa1NVa1BObkxJdHd5bXRMZzlDUklLTmdIVW54MVlmdQ==",
        },
      }
    );

    console.log("Access Token:", response.data.access_token);
    return response.data.access_token;
  } catch (error) {
    console.error("Error:", error.message);
    throw error;
  }
}
//getToken()
// set interval to refresh access token for match trade
setInterval(() => {
  getToken()
    .then((accessToken) => {
      authToken = accessToken;
    })
    .catch((error) => {
      console.error("Error:", error.message);
    });
}, 300000);

/**    Push to Mat Code Start */

async function sendLeadToMatchTrade(data) {
  try {
    const response = await axios.post(
      "https://bo-mtrwl.match-trade.com/documentation/process/api/accounts/sync",
      data,
      {
        headers: {
          Accept: "*/*",
          "Content-Type": "application/json",
          Authorization: `Bearer ${authToken}`,
        },
      }
    );

    return {
      status: response.status,
      data: response.data,
    };
  } catch (error) {
    console.error("Error:", error.response.data.message);
    return {
      data: error.response.data,
    };
  }
}
async function getLeadsFromMatchTrade(page) {
  const date = new Date().toISOString();
  try {
    const response = await axios.get(
      `https://bo-mtrwl.match-trade.com/documentation/account/api/partner/76/accounts/view?query=%40&from=2023-12-10T09:57:26.000Z&to=${date}&sort[sorted]=true&sort[unsorted]=true&sort[empty]=true&pageSize=0&pageNumber=${page}&paged=true&unpaged=true&offset=0`,

      {
        headers: {
          Accept: "*/*",
          "Content-Type": "application/json",
          Authorization: `Bearer ${authToken}`,
        },
      }
    );

    return {
      status: response.status,
      data: response.data.content,
    };
  } catch (error) {
    console.error("Error:", error.message);
    throw error;
  }
}

const getAllAccounts = async (source, fromDate, toDate) => {
  await getToken()
    .then((accessToken) => {
      console.log("Access Token:", accessToken);
      authToken = accessToken;
    })
    .catch((error) => {
      console.error("Error:", error.message);
    });
  const servertimenow = new Date().toISOString();
  const apiUrl = `https://bo-mtrwl.match-trade.com/documentation/account/api/partner/76/leads/view?from=${fromDate??'2023-12-20T08%3A12%3A57.533Z'}&to=${toDate??servertimenow}&size=1000&page=0&query=`;
  const headers = {
    accept: "*/*",
    Authorization: `Bearer ${authToken}`,
  };

  const response = await axios.get(apiUrl, { headers });
console.log(response.data.length);
  //console.log(response.data);
  const fileteredAccounts = response.data.content.filter((res)=>res?.leadInfo?.leadSource?.includes(source)??false)
  return fileteredAccounts
};

const getClientAccounts = async (email) => {
  const apiUrl = `https://bo-mtrwl.match-trade.com/documentation/account/api/partners/76/accounts/by-email?email=${email}`;
  const headers = {
    accept: "*/*",
    "Content-Type": "application/json",
    Authorization: `Bearer ${authToken}`,
  };

  try {
    const response = await axios.get(apiUrl, { headers });
    return {
      status: "SUCCESS",
      data: response.data,
    };
  } catch (error) {
    console.log("Error: ", error.response.data);
    return error.response.data;
  }
};

/**    Push to MatchTrade Code End */

/**    Push to Dialer code Start  */
async function pushToDialer(
  email,
  name,
  surname,
  phoneNumber,
  source,
  purchasesite,
  supportsite,
  country
) {
  console.log("Pushing to dialer");
  let date_ob = new Date();
  let date = ("0" + date_ob.getDate()).slice(-2);
  let month = ("0" + (date_ob.getMonth() + 1)).slice(-2);
  let year = date_ob.getFullYear();
  let hours = date_ob.getHours();
  let minutes = date_ob.getMinutes();
  let seconds = date_ob.getSeconds();
  let currentdate =
    year +
    "-" +
    month +
    "-" +
    date +
    " " +
    hours +
    ":" +
    minutes +
    ":" +
    seconds;
  const url = "http://mc.td.commpeak.com/api/leads";
  const urlmass = "https://mc.td.commpeak.com/api/campaign-leads/mass-assign";

  const username = "developer2";
  const password = "QddYW1F3wVOx";
  const credentials = btoa(`${username}:${password}`);

  const postData = [
    {
      first_name: name,
      last_name: surname,
      phone: phoneNumber,
      phone_normalized: phoneNumber,
      phone2: phoneNumber,
      phone_normalized2: phoneNumber,
      address1: "string",
      address2: "string",
      country: country,
      state: "string",
      city: "string",
      zip: "string",
      lat: "Unknown Type: float",
      lng: "Unknown Type: float",
      timezone: "string",
      original_identifier: "string",
      support_site: supportsite,
      purchase_site: purchasesite,
      purchase_date: currentdate,
      purchase_amount: "string",
      purchase_product_name: "string",
      purchase_card_name: "string",
      purchase_card_type: "string",
      purchase_card_digits: "string",
      email: email,
      birthdate: "string",
      loan_amount: "string",
    },
  ];

  console.log(postData);
  const options = {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Basic ${credentials}`,
    },
    body: JSON.stringify(postData),
  };

  try {
    await fetch(url, options)
      .then((response) => {
        if (!response.ok) {
          throw new Error(
            "Error occured while creating lead in dialer CRM:::::::: [" +
              response.status +
              "]"
          );
        }
        return response.json();
      })
      .then(async (data) => {
        // Process the response data here
        console.log("Sucessfully added lead; LeadID: ", data.leads[0].id);

        console.log("Successfully pushed lead to dialer");

        const putData = {
          where: {
            id: [data.leads[0].id],
          },
          campaign_id: campaignid,
          remove_from_others: true,
        };

        const optionsmass = {
          method: "PUT",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Basic ${credentials}`,
          },
          body: JSON.stringify(putData),
        };
        await fetch(urlmass, optionsmass)
          .then((response) => {
            console.log("Lead mass-assignment response:", response);
            if (!response.ok) {
              throw new Error(
                "Error occured during mass assign::::::: [" +
                  response.status +
                  "]"
              );
            }
            return response.json();
          })
          .then(async (data) => {
            const urlmassweight =
              "https://mc.td.commpeak.com/api/campaign-leads/update-campaign-leads";
            const campaignLeadId = Number(Object.keys(data.leads)[0]);
            console.log("Updating Campaign: ", campaignLeadId);
            console.log("Campaign LeadId:", campaignLeadId);
            const putDataW = {
              where: {
                id: [campaignLeadId],
              },
              update: {
                campaignLead: {
                  weight: "10000",
                },
              },
            };
            const optionsmassweight = {
              method: "PUT",
              headers: {
                "Content-Type": "application/json",
                Authorization: `Basic ${credentials}`,
              },
              body: JSON.stringify(putDataW),
            };
            await fetch(urlmassweight, optionsmassweight)
              .then(async (response) => {
                const data = await response.json();
                console.log(
                  "Response from Campaign Mass Update weight: ",
                  data
                );
              })
              .then((data) => {
                console.log(
                  "Dialer Push Successful!!!!!!! \n",
                  data,
                  putData,
                  putDataW
                );

                console.log(
                  "Lead push, mass assign and weight update successful"
                );
              });

            // Process the response data here
          })
          .catch(async (error) => {
            console.error("Error occurred during mass assign: ", error);
            console.error(await fetch(url, options));
          });
      })
      .catch(async (error) => {
        console.error("Error occurred during weight assign: ", error);
        console.error(await fetch(url, options));
      });

    return { status: "SUCCESS", message: "Successfully pushed to Dialer" };
  } catch (e) {
    throw new Error(`Error occured when pushing lead to dialer ${e}`);
  }
}

//Get Deposits

const getDeposits = async (fromDate, toDate) => {
  await getToken()
    .then((accessToken) => {
      //console.log("Access Token:", accessToken);
      authToken = accessToken;
    })
    .catch((error) => {
      console.error("Error:", error.message);
    });
  const servertimenow = new Date().toISOString();
  const apiUrl = `https://bo-mtrwl.match-trade.com/documentation/payment/api/partner/76/deposits/deposit-view-model?query=&from=${fromDate}&to=${toDate}&sort%5Bsorted%5D=true&sort%5Bunsorted%5D=true&sort%5Bempty%5D=true&pageSize=10&pageNumber=64&paged=true&unpaged=true&size=100`;
  const headers = {
    accept: "*/*",
    Authorization: `Bearer ${authToken}`,
  };

  const response = await axios.get(apiUrl, { headers });

  //console.log(response.data.content);
  return response.data.content;
};

/**    Push to Dialer Code End */

function verifyToken(req, res, next) {
  const token = req.header("Authorization");
  console.log(token);
  if (!token) {
    return res.status(401).json({ message: "Unauthorized - Missing token" });
  }

  jwt.verify(token.split(" ")[1], process.env.SECRET_KEY, (err, user) => {
    if (err) {
      if (err.name === "TokenExpiredError") {
        return res
          .status(403)
          .json({ message: "Forbidden - Token has expired" });
      } else {
        return res.status(403).json({ message: "Forbidden - Invalid token" });
      }
    }

    req.user = user;
    next();
  });
}

// Function to read user data from the JSON file
async function readUsersFile() {
  try {
    const data = fs.readFileSync("./users.json");
    return JSON.parse(data);
  } catch (error) {
    return [];
  }
}

// Function to write user data to the JSON file
async function writeUsersFile(user) {
  const users = JSON.parse(fs.readFileSync("./users.json"));
  if (users) {
    users.push(user);
    fs.writeFileSync("./users.json", JSON.stringify(users));
  } else {
    return "Couldn't write users";
  }
}

function formatDate(date) {
  if (new Date(date)) {
    return new Date(date).getTime();
  }
  const [datePart, timePart] = date.split(" ");
  let fday;
  let fmonth;
  let fyear;
  if (datePart.includes(".")) {
    const [day, month, year] = datePart.split(".").map(Number);
    fday = day;
    fmonth = month;
    fyear = year;
  } else if (datePart.includes("-")) {
    const [day, month, year] = datePart.split("-").map(Number);
    fday = day;
    fmonth = month;
    fyear = year;
  }

  const [hours, minutes, seconds] = timePart.split(":").map(Number);
  return new Date(fyear, fmonth - 1, fday, hours, minutes, seconds).getTime();
}
function generateRandomString() {
  const characters = "0123456789";
  let randomString = "";

  for (let i = 0; i < 12; i++) {
    const randomIndex = Math.floor(Math.random() * characters.length);
    randomString += characters.charAt(randomIndex);
  }

  return randomString;
}
app.post("/getAccessToken", async (req, res) => {
  const { username, password } = req.body;
  console.log(req.body);

  // Retrieve user data from the JSON file
  const users = await readUsersFile();
  console.log(users);

  // Find user by username
  const user = users.filter((u) => u.username === username)[0] ?? null;

  console.log(user);

  if (!user || user.password !== password) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  // Generate an access token
  const accessToken = jwt.sign(
    { user, dynamicElement: crypto.randomUUID() },
    process.env.SECRET_KEY,
    {
      expiresIn: "15m",
    }
  );
  console.log(accessToken);

  res.status(200).json({ accessToken });
});

app.post("/create-lead", verifyToken, async (req, res) => {
  const {
    email,
    name,
    surname,
    phoneNumber,
    source,
    purchasesite,
    supportsite,
    country,
    branchUuid,
    offerUuid,
    password,
  } = req.body;
  console.log(req.body);
  let adminUuid;
  let uuid;
  let suffix;
  try {
    var keys = JSON.parse(fs.readFileSync("./keys.json"));

    if (!keys) {
      console.log("INTERNAL SERVER ERROR:::CANT READ KEYS");
      return res.status(500).send("INTERNAL SERVER ERROR:::CANT READ KEYS");
    }

    if (!keys[0][purchasesite]) {
      adminUuid = crypto.randomUUID();
      keys[0][purchasesite] = adminUuid;

      fs.writeFileSync("./keys.json", JSON.stringify(keys));
    } else {
      adminUuid = keys[0][purchasesite];
    }
  } catch (error) {
    console.error("Error reading or parsing keys:", error);
    return res.status(500).send("INTERNAL SERVER ERROR:::CANT READ KEYS");
  }
  // try {
  //   var suffices = JSON.parse(fs.readFileSync("./suffix.json"));

  //   if (!suffices) {
  //     console.log("INTERNAL SERVER ERROR:::CANT READ SUFFICES");
  //     return res.status(500).send("INTERNAL SERVER ERROR:::CANT READ SUFFICES");
  //   }
  //   if (!adminUuid) {
  //     console.log("INTERNAL SERVER ERROR:::ADMIN UUID WAS NOT READ");
  //     return res
  //       .status(500)
  //       .send("INTERNAL SERVER ERROR:::ADMIN UUID WAS NOT READ");
  //   }
  //   if (!suffices[0][adminUuid]) {
  //     suffix = generateRandomString();
  //     suffices[0][adminUuid] = suffix;

  //     fs.writeFileSync("./suffix.json", JSON.stringify(suffices));
  //   } else {
  //     suffix = suffices[0][adminUuid];
  //   }

  //   //uuid = crypto.randomUUID().split('-').slice(0, -1).join('-') + '-' + suffix;
  // } catch (error) {
  //   console.error("Error reading or parsing suffices:", error);
  //   return res.status(500).send("INTERNAL SERVER ERROR:::CANT READ SUFFICES");
  // }
  await getToken()
    .then((accessToken) => {
      console.log("Access Token:", accessToken);
      authToken = accessToken;
    })
    .catch((error) => {
      console.error("Error:", error.message);
    });

  // if (!uuid) {
  //   console.log("INTERNAL SERVER ERROR:::CANT CREATE UUID");
  //   return res.status(500).send("INTERNAL SERVER ERROR:::CANT CREATE UUID");
  // }
  // if (!suffix) {
  //   console.log("INTERNAL SERVER ERROR:::CANT READ OR CREATE SUFFIX");
  //   return res
  //     .status(500)
  //     .send("INTERNAL SERVER ERROR:::CANT READ OR CREATE SUFFIX");
  // }
  (async () => {
    try {
      await pushToDialer(
        email,
        name,
        surname,
        phoneNumber,
        source,
        purchasesite,
        supportsite,
        country
      ).then(async (response) => {
        console.log("Did Dialer succeed: ", response);

        if (response.status == "SUCCESS") {
          const matchTradeData = {
            offerUuid: offerUuid,
            createAsDepositedAccount: false,
            accountManager: null,
            branchUuid: branchUuid,
            password: password,
            account: {
              //uuid: uuid,
              email: email,
              name: name,
              surname: surname,
              phone: phoneNumber,
              country: country,
              partnerId: 76,
              leadInfo: {
                leadSource: purchasesite,
              },
            },

            partnerId: 76,
          };
          console.log(matchTradeData);
          try {
            const response = await sendLeadToMatchTrade(matchTradeData);

            if (response.status === 200) {
              console.log({
                message: "Match Trade Account Created successfully",
                responseData: response,
              });
              res.status(200).send({
                statusCode: response.status,
                status: "SUCCESS",
                message: "Store this admin uuid in a safe place",
                adminUuid: adminUuid,
                data: {
                  account_uuid: response.data.uuid,
                  created: response.data.created,
                  email: response.data.email,
                  name: response.data.name,
                  surname: response.data.surname,
                },
              });
            } else {
              console.log("An error occurred while creating an account");
              console.log("Error:", response);
              if(response.data.status==="CONFLICT"){
              return  res
                .status(200)
                .send({"statusCode":200,"status":"FAILURE","message":"Duplicate error",});
              }
             return res
                .status(500)
                .send({ error: "INTERNAL_SERVER_ERROR", message: response });
            }
          } catch (error) {
            console.error("An error occurred: ", error.message);
            res
              .status(500)
              .send({ error: "INTERNAL_SERVER_ERROR", message: error.message });
          }
        }
      });
    } catch (e) {
      console.error("Erorr: ", e);
      res.status(500).send({ error: "INTERNAL_SERVER_ERROR", message: e });
      return;
    }
  })();
});
function isValidISOString(dateString) {
  const date = new Date(dateString);
  return date instanceof Date && !isNaN(date);
}
function isEarliestCreatedAtForAccount(deposit, allDeposits) {
  // Find the lead with the earliest createdAt for the same accountUuid
  const earliestCreatedAtDeposit = allDeposits.reduce(
    (earliestDeposit, otherDeposit) => {
      if (
        otherDeposit.accountUuid === deposit.accountUuid &&
        otherDeposit.status === "DONE" &&
        (!earliestDeposit ||
          new Date(otherDeposit.created) < new Date(earliestDeposit.created))
      ) {
        return otherDeposit;
      }
      return earliestDeposit;
    },
    null
  );

  // Check if the current lead has the earliest createdAt
  return (
    earliestCreatedAtDeposit &&
    new Date(deposit.created) === new Date(earliestCreatedAtDeposit.created)
  );
}
function getFirstDoneDeposits(deposits, source) {
  // Create an object to store deposits in buckets based on accountUuid
  const depositBuckets = {};

  // Sort deposits into buckets
  deposits.forEach((deposit) => {
    const accountUuid = deposit.accountUuid;

    // If the bucket for this accountUuid doesn't exist, create it
    if (!depositBuckets[accountUuid]) {
      depositBuckets[accountUuid] = [];
    }

    // Add the deposit to the bucket
    depositBuckets[accountUuid].push(deposit);
  });

  // Initialize an array to store the earliest "DONE" deposits with the specified suffix
  const earliestDoneDeposits = [];

  // Iterate through each bucket and select the "DONE" deposit with the earliest date and matching suffix
  Object.keys(depositBuckets).forEach((accountUuid) => {
    const depositsForAccount = depositBuckets[accountUuid];

    // Filter deposits with status "DONE" and matching suffix
    const doneDeposits = depositsForAccount.filter(
      (deposit) =>
        deposit.status === "DONE" && deposit.accountLeadSource?.includes(source)
    );

    if (doneDeposits.length > 0) {
      // Sort "DONE" deposits by date in ascending order
      const sortedDoneDeposits = doneDeposits.sort(
        (a, b) => new Date(a.created) - new Date(b.created)
      );

      // Add the earliest "DONE" deposit to the result array
      earliestDoneDeposits.push(sortedDoneDeposits[0]);
    }
  });

  return earliestDoneDeposits;
}

app.get("/ftd-clients", verifyToken, async (req, res) => {
  const { adminUuid, fromDate, toDate } = req.body;
  let source;
  console.log(req.body);
  if (
    !adminUuid ||
    isValidISOString(fromDate) === false ||
    isValidISOString(toDate) === false
  ) {
    console.log("DATE OR ADMIN UUID IS INCORRECT");
    return res.status(400).send("BAD REQUEST:::::CHECK REQUEST BODY");
  }
  let suffix;
  try {
    var keys = JSON.parse(fs.readFileSync("./keys.json"));

    if (!keys) {
      console.log("INTERNAL SERVER ERROR:::CANT READ KEYS");
      return res.status(500).send("INTERNAL SERVER ERROR:::CANT READ KEYS");
    }
    console.log(keys);

    Object.keys(keys[0]).forEach((key) => {
      if (keys[0][key] === adminUuid) {
        console.log(key);
        source = key;
      }
    });

    if (!source) {
      console.log("ADMIN UUID IS NOT FOUND IN STORE");
      return res.status(400).send("ADMIN UUID IS NOT FOUND IN STORE");
    }
  } catch (error) {
    console.error("Error reading or parsing suffices:", error);
    return res.status(500).send("INTERNAL SERVER ERROR:::CANT READ SUFFICES");
  }
  await getToken()
    .then((accessToken) => {
      //console.log("Access Token:", accessToken);
      authToken = accessToken;
    })
    .catch((error) => {
      console.error("Error:", error.message);
    });
  const allLeads = [];
  const allDeposits = [];

  try {
    const deposits = await getDeposits(fromDate, toDate);
    allDeposits.push(...deposits);

    const filteredDeposits = getFirstDoneDeposits(allDeposits, source);
    console.log("Filtered deposits:", filteredDeposits.length);
    const formattedDeposits = [];
    filteredDeposits.forEach((deposit) => {
      formattedDeposits.push({
        uuid: deposit.uuid,
        accountUuid: deposit.accountUuid,
        ftd_date: deposit.created,
        amount: deposit.amount,
        status: deposit.status,
        email: deposit.email,
      });
    });

    res.status(200).send({ data: formattedDeposits, message: "SUCCESS" });
  } catch (e) {
    console.error("Error: ", e);
    res
      .status(500)
      .send({ error: "INTERNAL_SERVER_ERROR", message: e.message });
  }
});

app.get("/accounts-by-emails", verifyToken, async (req, res) => {
  const { adminUuid, emails } = req.body;
  let source;
  console.log(req.body);
  if (!adminUuid || !Array.isArray(emails)) {
    console.log("ADMIN UUID OR EMAILS NOT ADDED");
    return res.status(400).send("BAD REQUEST:::::CHECK REQUEST BODY");
  }
  let suffix;
  try {
    var keys = JSON.parse(fs.readFileSync("./keys.json"));

    if (!keys) {
      console.log("INTERNAL SERVER ERROR:::CANT READ KEYS");
      return res.status(500).send("INTERNAL SERVER ERROR:::CANT READ KEYS");
    }
    console.log(keys);

    Object.keys(keys[0]).forEach((key) => {
      if (keys[0][key] === adminUuid) {
        console.log(key);
        source = key;
      }
    });

    if (!source) {
      console.log("ADMIN UUID IS NOT FOUND IN STORE");
      return res.status(400).send("ADMIN UUID IS NOT FOUND IN STORE");
    }
  } catch (error) {
    console.error("Error reading or parsing suffices:", error);
    return res.status(500).send("INTERNAL SERVER ERROR:::CANT READ SUFFICES");
  }

  let emailsProcessed = 0;

  try {
    await getToken()
      .then((accessToken) => {
        authToken = accessToken;
      })
      .catch((error) => {
        console.error("Error:", error.message);
      });

    const accountPromises = emails.map(async (email) => {
      try {
        const account = await getClientAccounts(email);
        if (account.status === "SUCCESS") {
          return account.data;
        }
      } catch (error) {
        console.error(
          `Error getting account: email : ${email}:`,
          error.message
        );
      } finally {
        emailsProcessed++;

        if (emailsProcessed % 20 === 0) {
          await getToken()
            .then((accessToken) => {
              authToken = accessToken;
            })
            .catch((error) => {
              console.error("Error refreshing token:", error.message);
            });
        }
      }
    });

    const allAccounts = await Promise.all(accountPromises);
    console.log(allAccounts);
    const filteredAccounts = allAccounts.filter(
      (acc) => acc?.leadInfo?.leadSource?.includes(source) ?? false
    );

    return res.status(200).send({ data: filteredAccounts, message: "SUCCESS" });
  } catch (error) {
    console.log("INTERNAL SERVER ERROR::::CANT GET ACCOUNTS");
    return res.status(500).send("INTERNAL SERVER ERROR::::CANT GET ACCOUNTS");
  }
});

app.get("/accounts", verifyToken, async (req, res) => {
  const { adminUuid, fromDate, toDate } = req.body;
  let source;
  console.log(req.body);
  
  if (!adminUuid) {
    console.log("ADMIN UUID NOT ADDED");
    return res.status(400).send("BAD REQUEST:::::CHECK REQUEST BODY");
  }
  if((fromDate&&!isValidISOString(fromDate))||(toDate&&!isValidISOString(toDate))){
    console.log("WRONG DATE FRORMAT");
    return res.status(400).send("BAD REQUEST:::::DATE FORMAT MUST BE ISO STRING");
  }
  if(new Date(fromDate)< new Date("2023-12-21T00:00:00.000Z")){
    console.log("OUT OF RANGE");
    return res.status(400).send("BAD REQUEST:::::DATE IS OUT OF RANGE");
  }
  let suffix;
  try {
    var keys = JSON.parse(fs.readFileSync("./keys.json"));

    if (!keys) {
      console.log("INTERNAL SERVER ERROR:::CANT READ KEYS");
      return res.status(500).send("INTERNAL SERVER ERROR:::CANT READ KEYS");
    }
    console.log(keys);

    Object.keys(keys[0]).forEach((key) => {
      if (keys[0][key] === adminUuid) {
        console.log(key);
        source = key;
      }
    });

    if (!source) {
      console.log("ADMIN UUID IS NOT FOUND IN STORE");
      return res.status(400).send("ADMIN UUID IS NOT FOUND IN STORE");
    }
  } catch (error) {
    console.error("Error reading or parsing suffices:", error);
    return res.status(500).send("INTERNAL SERVER ERROR:::CANT READ SUFFICES");
  }



  try {
    const filteredAccounts = await getAllAccounts(source, fromDate, toDate)
    console.log(filteredAccounts.length);

    return res.status(200).send({ data: filteredAccounts, message: "SUCCESS" });
  } catch (error) {
    console.log("INTERNAL SERVER ERROR::::CANT GET ACCOUNTS");
    return res.status(500).send("INTERNAL SERVER ERROR::::CANT GET ACCOUNTS");
  }
});

// app.get("/", (req,res)=>{
//   return res.json({message:"hello"})
// })

module.exports = app;
