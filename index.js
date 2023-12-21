const express = require('express');
const app = require('./sheets_proccessor');

const port =  8080;



app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
