const express = require("express");
const morgan = require("morgan");
const helmet = require("helmet");
const cors = require("cors");
const axios = require("axios");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const fs = require("fs");
require("dotenv").config();
const bodyParser = require("body-parser");
const admin = require("firebase-admin");
const credentials = require("./service_key.json");

admin.initializeApp({
  credential: admin.credential.cert(credentials),
});

const db = admin.firestore();

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

const ignoreBranches = [
  "55b51d62-0461-4d42-b20d-82ec7027837d",
  "7f04a46c-483b-42ba-b2b0-c3d2e942cc00",
  "3c533c31-07ca-4359-bf40-c66489aac9c3",
  "2b5272e7-982a-45e6-973e-7d6ac2e86704",
];

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

const getDailerLeads = async (source) => {
  let allLeads = [];

  try {
    let offset = 0;
    let hasMoreLeads = true;

    while (hasMoreLeads) {
      const apiUrl = `https://mc.td.commpeak.com/api/leads/limit/500;${offset}/purchase_site/${source}/created_at/2023-12-21%2013:15:11;>`;
      const headers = {
        accept: "*/*",
        Authorization: `Basic ${btoa("developer2:QddYW1F3wVOx")}`,
        "Content-Type": "application/json",
      };
      const response = await axios.get(apiUrl, { headers });
      const leads = response.data.leads;

      if (leads.length === 0 || leads.length < 500) {
        // If there are no more leads or the number of leads is less than 500, stop the loop
        hasMoreLeads = false;
      }

      allLeads.push(...leads);
      offset += 500;
    }

    console.log(`Total number of leads: ${allLeads.length}`);
    if (allLeads.length > 0) {
      console.log(`Last lead ID: ${allLeads[allLeads.length - 1].email}`);
    }

    return allLeads;
  } catch (error) {
    console.log(error.response.data);
    return [];
  }
};

const getAgentComments = async (leadId, agentsList) => {
  try {
    const apiUrl = `https://mc.td.commpeak.com/api/comments/lead_id/${leadId}/`;
    const headers = {
      accept: "application/json",
      Authorization: `Basic ${btoa("developer2:QddYW1F3wVOx")}`,
      "Content-Type": "application/json",
    };
    const response = await axios.get(apiUrl, { headers });

    const comments = response.data.comments;
    const filteredComments = comments.filter((comment) =>
      agentsList.includes(comment.creator_user_id)
    );
    filteredComments.sort(
      (a, b) => new Date(b.created_at) - new Date(a.created_at)
    );

   // console.log(filteredComments[0]);
    return filteredComments[0];
  } catch (error) {
   // console.log("Error: ", error.response.data);
    return { body: "No answer or no comment" };
  }
};
const getAllUsers = async (id) => {
  try {
    const apiUrl = `https://mc.td.commpeak.com/api/users`;
    const headers = {
      accept: "application/json",
      Authorization: `Basic ${btoa("developer2:QddYW1F3wVOx")}`,
      "Content-Type": "application/json",
    };
    const response = await axios.get(apiUrl, { headers });
    const users = response.data.users.filter((obj) => {
      return obj.desks && Object.keys(obj.desks).includes("5");
    });

    const secondCampaignAgents = users.map((u) => u.id);
    return secondCampaignAgents;
  } catch (error) {
    console.log("Error: ", error.response.data);
    return [];
  }
};

const getAllAccounts = async (source, fromDate, toDate) => {
  // const dailerAccounts = await getDailerLeads(source);
  // const allAgents = await getAllUsers();
  await getToken()
    .then((accessToken) => {
      console.log("Access Token:", accessToken);
      authToken = accessToken;
    })
    .catch((error) => {
      console.error("Error:", error.message);
    });

  const accounts = [];
  let currentPage = 0;
  let totalPages = 1;

  do {
    const servertimenow = new Date().toISOString();
    const apiUrl = `https://bo-mtrwl.match-trade.com/documentation/account/api/partner/76/leads/view?from=${
      fromDate ?? "2023-12-21T00%3A00%3A00Z"
    }&to=${toDate ?? servertimenow}&size=2000&page=${currentPage}&query`;
    const headers = {
      accept: "*/*",
      Authorization: `Bearer ${authToken}`,
    };

    const response = await axios.get(apiUrl, { headers });
    totalPages = response.data.totalPages;
    const currentPageAccounts = response.data.content;
    for (let i = 0; i < currentPageAccounts.length; i++) {
      if (currentPageAccounts[i]?.leadSource === source) {
        // let comment;
        // const dailerAccount = dailerAccounts.find(
        //   (d) => d.email == currentPageAccounts[i].email
        // );

        // if (dailerAccount!=undefined) {
        //   comment = await getAgentComments(dailerAccount.id, allAgents);
        // }
       

        accounts.push({
          uuid: currentPageAccounts[i].uuid,
          created: currentPageAccounts[i].created,
          updated: currentPageAccounts[i].updated,
          leadInfo: {
            leadSource: currentPageAccounts[i].leadSource,
          },
          email: currentPageAccounts[i].email,
          branchUuid: currentPageAccounts[i].branchUuid,
          name: currentPageAccounts[i].name,
          surname: currentPageAccounts[i].surname,
          phone: currentPageAccounts[i].phone,
          country: currentPageAccounts[i].country,
          role: currentPageAccounts[i].role,
          leadStatus: currentPageAccounts[i].leadStatus,
          leadSource: currentPageAccounts[i].leadSource,
          //lastComment: comment?.body ?? "",
        });
      }
    }
    currentPage++;
  } while (currentPage < totalPages);

  console.log("Total accounts:", accounts.length);
  // const fileteredAccounts = accounts.filter(
  //   (res) => res?.leadInfo?.leadSource === source ?? false
  // );
  console.log("Total filtered accounts:", accounts.length);

  return accounts;
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
  country,
  campaignid
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

  const deposits = [];
  let currentPage = 0;
  let totalPages = 1;

  do {
    const servertimenow = new Date().toISOString();
    const apiUrl = `https://bo-mtrwl.match-trade.com/documentation/payment/api/partner/76/deposits/deposit-view-model?from=${
      fromDate ?? "2023-12-21T00%3A00%3A00Z"
    }&to=${toDate ?? servertimenow}&size=2000&page=${currentPage}&query`;

    const headers = {
      accept: "*/*",
      Authorization: `Bearer ${authToken}`,
    };

    const response = await axios.get(apiUrl, { headers });
    totalPages = response.data.totalPages;
    // console.log(totalPages);
    const currentPageDeposits = response.data.content;

    deposits.push(...currentPageDeposits);
    currentPage++;
  } while (currentPage < totalPages);

  console.log("Total deposits:", deposits.length);
  return deposits;
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

// Write document to firestore
const writeToFirestore = async (collectionname, purchasesite, data) => {
  try {
    await db.collection(collectionname).doc(purchasesite).set(data);
    console.log("Successfully wrote to firestore");
  } catch (e) {
    console.log(e);
    throw e;
  }
};

// Read document from firestore
const readFromFirestore = async (collectionname, doc) => {
  try {
    const res = await db.collection(collectionname).doc(doc).get();
    if (res.exists) {
      const map = res.data();
      return map[doc];
    }
  } catch (e) {
    console.log(e);
    throw e;
  }
};
// Read All document from firestore
const readAllFromFirestore = async (collectionname) => {
  try {
    const res = await db.collection(collectionname).get();
    const resarr = res.docs.map((doc) => doc.data());
    return resarr;
  } catch (e) {
    console.log(e);
    throw e;
  }
};

app.post("/getAccessToken", async (req, res) => {
  const { username, password } = req.body;
  console.log(req.body);

  const users = await readAllFromFirestore("users");
  console.log(users);

  const user = users.filter((u) => u.username === username)[0] ?? null;

  console.log(user);

  if (!user || user.password !== password) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

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
    password,
  } = req.body;
  console.log(req.body);
  let adminUuid;
  let uuid;
  let suffix;
  try {
    adminUuid = await readFromFirestore("keys", purchasesite);

    if (!adminUuid) {
      adminUuid = crypto.randomUUID();

      await writeToFirestore("keys", purchasesite, {
        [purchasesite]: adminUuid,
      }).catch((e) => {
        throw e;
      });
    }
  } catch (error) {
    console.error("Error reading/writing keys:", error);
    return res.status(500).send("INTERNAL SERVER ERROR:::CANT READ/WRITE KEYS");
  }

  await getToken()
    .then((accessToken) => {
      console.log("Access Token:", accessToken);
      authToken = accessToken;
    })
    .catch((error) => {
      console.error("Error:", error.message);
    });

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
        country,
        13
      ).then(async (response) => {
        console.log("Did Dialer succeed: ", response);

        if (response.status == "SUCCESS") {
          const matchTradeData = {
            offerUuid: "d04e7df5-9ad4-4979-b4bc-5045c73a2cc7",
            createAsDepositedAccount: false,
            accountManager: null,
            password: password,
            account: {
              //uuid: uuid,
              email: email,
              name: name,
              branchUuid: "6deb5d8d-4636-4225-b64f-09310dab53b7",
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
              console.log("Push to sheets");
              //Push to All leads 2 sheet
              const tbpDate = new Date().toISOString();
              fetch(
                "https://sheet.best/api/sheets/c9adf0ee-f4da-4bfc-9d8e-4dbce9268884", //All Leads 2 Sheet
                {
                  method: "POST",
                  mode: "cors",
                  headers: {
                    "Content-Type": "application/json",
                  },
                  body: JSON.stringify({
                    Name: name,
                    Surname: surname,
                    Email: email,
                    Phone: phoneNumber,
                    Created_At: tbpDate,
                    Source: purchasesite,
                  }),
                }
              )
                .then((r) => r.json())
                .then((data) => {
                  console.log(
                    "Added to All Leads 2 sheet successfully: ",
                    data
                  );
                })
                .catch((error) => {
                  console.error(error);
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
              if (response.data.status === "CONFLICT") {
                return res.status(200).send({
                  statusCode: 200,
                  status: "FAILURE",
                  message: "Duplicate error",
                });
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

function getFirstDoneDeposits(deposits, source) {
  const depositBuckets = {};

  deposits.forEach((deposit) => {
    const accountUuid = deposit.accountUuid;

    if (!depositBuckets[accountUuid]) {
      depositBuckets[accountUuid] = [];
    }

    depositBuckets[accountUuid].push(deposit);
  });

  const earliestDoneDeposits = [];

  Object.keys(depositBuckets).forEach((accountUuid) => {
    const depositsForAccount = depositBuckets[accountUuid];

    const doneDeposits = depositsForAccount.filter(
      (deposit) =>
        deposit.status === "DONE" && deposit.accountLeadSource === source
    );

    if (doneDeposits.length > 0) {
      const sortedDoneDeposits = doneDeposits.sort(
        (a, b) => new Date(a.created) - new Date(b.created)
      );

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
    const keys = await readAllFromFirestore("keys");

    if (!keys) {
      console.log("INTERNAL SERVER ERROR:::CANT READ KEYS");
      return res.status(500).send("INTERNAL SERVER ERROR:::CANT READ KEYS");
    }
    console.log(keys);
    ouuterLoop: for (const obj of keys) {
      for (const key in obj) {
        if (obj[key] === adminUuid) {
          source = key;
          break ouuterLoop;
        }
      }
    }

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
    const formattedDeposits = await Promise.all(
      filteredDeposits.map(async (deposit) => {
        const response = await getClientAccounts(deposit.email);
        console.log({
          branchUuid: response.data.branchUuid,
          uuid: deposit.uuid,
          accountUuid: deposit.accountUuid,
          ftd_date: deposit.created,
          amount: deposit.amount,
          status: response.data.leadStatus.name,
          email: deposit.email,
        });
        if (!ignoreBranches.includes(response.data.branchUuid)) {
          return {
            uuid: deposit.uuid,
            accountUuid: deposit.accountUuid,
            ftd_date: deposit.created,
            amount: deposit.amount,
            status: response.data.leadStatus.name,
            email: deposit.email,
          };
        }
      })
    );
    const notNullDeposits = formattedDeposits.filter((d) => d != null);
    res.status(200).send({
      amount: notNullDeposits.length,
      data: notNullDeposits,
      message: "SUCCESS",
    });
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
  try {
    const keys = await readAllFromFirestore("keys");

    if (!keys) {
      console.log("INTERNAL SERVER ERROR:::CANT READ KEYS");
      return res.status(500).send("INTERNAL SERVER ERROR:::CANT READ KEYS");
    }
    console.log("Keys: ", keys);
    ouuterLoop: for (const obj of keys) {
      for (const key in obj) {
        if (obj[key] === adminUuid) {
          source = key;
          break ouuterLoop;
        }
      }
    }

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
      (acc) => acc?.leadInfo?.leadSource === source ?? false
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
  if (
    (fromDate && !isValidISOString(fromDate)) ||
    (toDate && !isValidISOString(toDate))
  ) {
    console.log("WRONG DATE FRORMAT");
    return res
      .status(400)
      .send("BAD REQUEST:::::DATE FORMAT MUST BE ISO STRING");
  }
  // if(new Date(fromDate)< new Date("2023-12-21T00:00:00.000Z")){
  //   console.log("OUT OF RANGE");
  //   return res.status(400).send("BAD REQUEST:::::DATE IS OUT OF RANGE");
  // }
  try {
    const keys = await readAllFromFirestore("keys");

    if (!keys) {
      console.log("INTERNAL SERVER ERROR:::CANT READ KEYS");
      return res.status(500).send("INTERNAL SERVER ERROR:::CANT READ KEYS");
    }
    console.log("Keys: ", keys);
    ouuterLoop: for (const obj of keys) {
      for (const key in obj) {
        if (obj[key] === adminUuid) {
          source = key;
          break ouuterLoop;
        }
      }
    }

    if (!source) {
      console.log("ADMIN UUID IS NOT FOUND IN STORE");
      return res.status(400).send("ADMIN UUID IS NOT FOUND IN STORE");
    }
  } catch (error) {
    console.error("Error reading or parsing suffices:", error);
    return res.status(500).send("INTERNAL SERVER ERROR:::CANT READ SUFFICES");
  }

  try {
    console.log("Source:   ", source);
    const filteredAccounts = await getAllAccounts(source, fromDate, toDate);
    console.log(filteredAccounts.length);

    return res.status(200).send({
      amount: filteredAccounts.length,
      data: filteredAccounts,
      message: "SUCCESS",
    });
  } catch (error) {
    console.log("INTERNAL SERVER ERROR::::CANT GET ACCOUNTS");
    return res.status(500).send("INTERNAL SERVER ERROR::::CANT GET ACCOUNTS");
  }
});

// app.get("/", (req,res)=>{
//   return res.json({message:"hello"})
// })

module.exports = app;
