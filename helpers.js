
const axios = require("axios");


var authToken = "";

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

    // console.log("Access Token:", response.data.access_token);
    return response.data.access_token;
  } catch (error) {
    console.error("Error:", error.message);
    throw error;
  }
}
async function partialUpdate(uid, status) {
  const statusMappings = {
    "Active client": "ACTIVE_CLIENT",
    "System - Answer (Dropped)": "NO_POTENTIAL",
    "Invalid Phone": "NO_POTENTIAL",
    "Failed To Connect": "NO_POTENTIAL",
    Duplicate: "NO_POTENTIAL",
    "Do Not Call": "NO_POTENTIAL",
    Underage: "NO_POTENTIAL",
    "Hang up": "NEED_ANALYSIS",
    Declined: "NEED_ANALYSIS",
    "Language Barrier": "NEED_ANALYSIS",
    "Wrong person": "NEED_ANALYSIS",
    "Not Interested": "NEED_ANALYSIS",
    Deposit: "READY_TO_DEPOSIT",
    VoiceMail: "CONTACTED",
    "Personal Meeting": "CONTACTED",
    "General Meeting": "CONTACTED",
    Busy: "CONTACTED",
    "No Answer": "CONTACTED",
    "Default Status": "NEW_CONTACT",
    "New Contact": "NEW_CONTACT",
  };

  const statusIdMap = {
    Busy: "b6ec2c12-5718-438e-b7f9-feb0d522ac91",
    "Invalid Phone": "fe5bc8db-6130-48a5-a5bc-47a9695ffa59",
    Duplicate: "e89cecdf-c067-4043-837d-4fb5cb6e1965",
    "Do Not Call": "a676dd45-c32d-4c77-89cc-a3c497640d13",
    "New Contact": "76fb9159-e5b5-4d02-8f4e-222c4d5bc042",
    "Personal Meeting": "919090a5-42f5-4086-905f-b2f93feb89d3",
    "General Meeting": "917e278c-5d0c-43e0-93d8-1fdf84bb74b2",
    "Default Status": "8461fa3c-2c23-4dfd-aac1-c4e8c0b65b72",
    "Language Barrier": "fe9a8018-96d0-40de-b51e-8f473c95613d",
    "Failed To Connect": "8b363d9e-cc7d-41fb-a503-5ba6c00f34cb",
    Deposit: "d5e65291-3911-41e9-86a7-70c6c95c856e",
    "No Answer": "d118305a-fc6b-42e1-98e6-96181c2822ad",
    "Not Interested": "1a7b52e1-adae-4a2e-b158-4f43d75e3da4",
    Underage: "64dcfbf6-3f9f-494d-9e60-bcb67c136006",
    "System - Answer (Dropped)": "cd2b1cb9-2bfa-4b2d-86e1-af2449cebb33",
    "Hang up": "1425f8e1-25e4-4399-9f34-bde5e0c154e2",
    Declined: "998561cb-69ff-489a-80a9-31d21cf12112",
    "Wrong person": "9d4f5924-5e30-4cc3-88c0-62f4987aa03b",
    VoiceMail: "5820dff9-5891-4871-91ae-c5d10f6d74be",
    "Active client": "65f61006-93f8-4f20-94df-b642f70c9038",
  };
  await getToken()
    .then((accessToken) => {
      //console.log("Access Token:", accessToken);
      authToken = accessToken;
    })
    .catch((error) => {
      console.error("Error:", error.message);
    });
  //console.log(authToken);
  console.log("Status is:::::::::: ", status);
  console.log("Status Mappings is:::::::::: ", statusMappings[status]);
  console.log("Status id map is:::::::::: ", statusIdMap[status]);
  const servertimenow = new Date().toISOString();
  try {
    const response = await axios.patch(
      `https://bo-mtrwl.match-trade.com/documentation/account/api/partners/76/accounts/${uid}`,
      JSON.stringify({
        leadStatus: {
          leadStage:
            status === "Deposit"
              ? "CONTACTED"
              : statusMappings[status] || statusMappings["Default Status"],
          name: status === "Deposit" ? "Personal Meeting" : status,
          enabled: true,
          uuid:
            status === "Deposit"
              ? statusIdMap["Personal Meeting"]
              : statusIdMap[status] || statusIdMap["Default Status"],
          partnerId: 76,
          updated: servertimenow,
        },
      }),
      {
        headers: {
          Accept: "*/*",
          "Content-Type": "application/json",
          Authorization: `Bearer ${authToken}`,
        },
      }
    );
    console.log({
      status: response.status,
      //data: response.data,
    });

    return {
      status: response.status,
      data: response.data,
    };
  } catch (error) {
    console.log("Error:", error.response.data);
  }
}

const getDailerCampaignLeads = async (id, campaign_id) => {
  const apiUrl = `https://mc.td.commpeak.com/api/campaign-leads/limit/2/order/created_at/lead_id/${id}`;
  const headers = {
    accept: "*/*",
    Authorization: `Basic ${btoa("developer2:QddYW1F3wVOx")}`,
    "Content-Type": "application/json",
  };

  try {
    const response = await axios.get(apiUrl, { headers });
    //console.log(response.data.campaignLeads);
    // console.log(
    //   response.data.campaignLeads[response.data.campaignLeads.length - 1]
    // );
    const filteredAcc = response.data.campaignLeads.filter(
      (acc) => acc.campaign_id === campaign_id
    );
    console.log(filteredAcc[filteredAcc.length - 1]);
    return filteredAcc[filteredAcc.length - 1];
  } catch (error) {
    console.log(error.response.data);
    return null;
  }
};

const getAllAccounts3 = async (source, fromDate, toDate) => {
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

    accounts.push(...currentPageAccounts);
    currentPage++;
  } while (currentPage < totalPages);

  //console.log("Total accounts:", accounts.length);
  const fileteredAccounts = accounts.filter(
    (res) => res?.leadInfo?.leadSource?.includes(source) ?? false
  );
  // console.log(
  //   "Total filtered accounts:",
  //   fileteredAccounts.find(
  //     (acc) => acc.uuid === "56da8bca-4f51-4c82-92fd-f02b49884e17"
  //   )
  // );
  return fileteredAccounts;
};

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

 const updateSelectAccounts = async (source) => {
  // const statusMap = {
  //   1: "Busy",
  //   8: "Invalid Phone",
  //   5: "Duplicate",
  //   4: "Do Not Call",
  //   10: "New Contact",
  //   13: "Personal Meeting",
  //   7: "General Meeting",
  //   2: "Default Status",
  //   9: "Language Barrier",
  //   6: "Failed To Connect",
  //   3: "Deposit",
  //   11: "No Answer",
  //   12: "Not Interested",
  // };

  const statusMap = {
    103: "Busy",
    104: "Default Status",
    105: "Deposit",
    106: "Do Not Call",
    107: "Duplicate",
    108: "Failed To Connect",
    109: "General Meeting",
    110: "Hang up",
    111: "Interested",
    112: "Invalid Phone",
    113: "Language Barrier",
    114: "New Contact",
    115: "No Answer",
    116: "Not Interested",
    117: "Personal Meeting",
    118: "System - Answer (Dropped)",
    119: "Underage",
    120: "VoiceMail",
    121: "Wrong Person",
    1: "Busy",
    2: "Default Status",
    3: "Deposit",
    4: "Do Not Call",
    5: "Duplicate",
    6: "Failed To Connect",
    7: "General Meeting",
    19: "Hang up",
    20: "Interested",
    8: "Invalid Phone",
    9: "Language Barrier",
    10: "New Contact",
    11: "No Answer",
    12: "Not Interested",
    13: "Personal Meeting",
    14: "System - Answer (Dropped)",
    15: "Underage",
    16: "VoiceMail",
    17: "Wrong Person",
  };

  let totalAccUpdated = 0;

  try {
    const dailerAccounts = await getDailerLeads(source);
    const accounts = await getAllAccounts3(source);

    console.log("Total MT Accounts: ", accounts.length);
    console.log("Total Dailer Accounts: ", dailerAccounts.length);

    for (const dacc of dailerAccounts) {
      const mtAccount = accounts.find((acc) => acc.email === dacc.email);

      if (mtAccount && mtAccount.leadStatus !== "Deposit") {
        console.log("Found MT Account...");
        const campaLead = await getDailerCampaignLeads(dacc.id, "13");

        if (campaLead) {
          await partialUpdate(
            mtAccount.uuid,
            statusMap[campaLead.status_id] ?? "Default Status"
          );
          console.log(
            `Updated account ${mtAccount.email} with status ${
              statusMap[campaLead.status_id]
            }`
          );
          totalAccUpdated++;
        }
      } else {
        if (mtAccount?.leadStatus === "Deposit") {
          console.log("MT Account has Deposit status already...");
        }
        console.log("MT Account Not Found...");
      }
    }

    console.log("Update completed successfully.");
    console.log("Total Updates: ", totalAccUpdated);
  } catch (error) {
    console.error("Error in updateSelectAccounts:", error);
  }
};

module.exports=updateSelectAccounts