const express = require('express');
const app = require('./sheets_proccessor');

const port = process.env.PORT || 80;



app.listen(8080, () => {
  console.log(`Server is running on port ${port}`);
});
