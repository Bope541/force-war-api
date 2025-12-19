const express = require('express');
const app = express();

app.get('/health', (req, res) => res.json({ ok: true }));
app.get('/', (req, res) => res.send('API ONLINE'));

const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => {
  console.log('API ESCUTANDO', PORT);
});

