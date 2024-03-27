
const app = require("./sheets_proccessor");

const updateSelectAccounts = require("./helpers")
const port = process.env.PORT || 80;



async function repeatUpdate() {
  await updateSelectAccounts("TMS");
  setTimeout(repeatUpdate, 1800000);
}

repeatUpdate(); 

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
