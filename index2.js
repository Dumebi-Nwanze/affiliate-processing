
const app = require("./sheets_proccessor");
const updateSelectAccounts = require("./helpers")

const port = process.env.PORT2 || 90;


async function repeatUpdate() {
  await updateSelectAccounts("a-crv");
  setTimeout(repeatUpdate, 1800000);
}

repeatUpdate(); 

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
