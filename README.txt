# API Documentation

## 1. Authentication

To access the API, you need to use a username and password to obtain an access token. The access token has a validity of 15 minutes, so make sure to fetch a new one for each request.

## 2. Add a Lead

To add a lead, make a `POST` request to the `/create-lead` endpoint with the following fields in the request body:

Endpoint: `/create-lead`

**Request Body:**
```json
{
  "email": "user@example.com",
  "name": "John",
  "surname": "Doe",
  "phoneNumber": "123456789",
  "regdate": "2023-01-01",
  "source": "web",
  "purchasesite": "a-fb-campaign",
  "supportsite": "support.example.com",
  "campaignid": "123",
  "branchUuid": "branch-123",
  "offerUuid": "offer-456",
  "password": "securePassword"
}
```

## 3. Get Leads with FTD Deposit

To retrieve leads with FTD (First Time Deposit), make a `POST` request to the `/leads` endpoint with the admin UUID in the request body.

Endpoint: `/leads`

**Request Body:**
```json
{
  "adminUuid": "yourAdminUuid"
}
```

## 4. Retrieve Admin UUID

An endpoint will be provided to retrieve the admin UUID. Make a request to this endpoint with your authentication credentials (the same ones used to obtain the access token).

Root IP: `167.172.98.191`

**Note:** Keep your admin UUID secure and do not share it.

## 5. Retrieve Admin UUID from Lead Creation

Alternatively, you can retrieve the admin UUID from the response when creating a lead. After making a successful `POST` request to the `/create-lead` endpoint, check the response for the admin UUID.

Endpoint: `/create-lead`

**Example Response:**
```json
{
  "message": "SUCCESS",
  "adminUuid": "yourAdminUuid"
}
```

This allows you to obtain the admin UUID immediately after creating a lead without making an additional request.

Remember to keep your admin UUID secure and do not expose it unnecessarily.