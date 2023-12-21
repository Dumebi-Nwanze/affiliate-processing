1. A username and password will be given to you, this is what you will use to get the access Token.

2. The access Token lasts for only 15 minutes so you will need to fetch it every time you make a request.

3. To add a lead you will supply the followinf fields to the /create-lead endpoint. This is a POST request.

4. To get you leads you will need to make a POST request to the /leads endpoint. You will pass you admin uuid in the body of the request.

5. An endpoint will be provided to retieve this admin uuid, you will make a request to this endpoint with your authentication credentials.
The same one used to get the authentication token

6. make sure to keep your admin uuid safe

Root IP: 167.172.98.191
Create Leads : /create-lead
Body:  {
 email,
    name,
    surname,
    phoneNumber,
    regdate,
    source,
    purchasesite,
    supportsite,
    campaignid,
    branchUuid,
    offerUuid,
    password,
}
Get Leads with FTD Deposit: /leads
Body: {
adminUuid
}

