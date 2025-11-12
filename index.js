require('dotenv').config();
const express = require('express');
const fetch = require('node-fetch');
const cors = require('cors');

const app = express();
const port = 3000;

// allows all cross-origin requests
app.use(cors())

// allow for json parsing of large dataURLs
app.use(express.json({ limit: '20mb' }));

async function analyseImage(dataURL) {
  // use the Gemini Vision API
  const base64Data = dataURL.split(',')[1];

  const body = {
    contents : [{
      parts: [
          { text: "What is this picture?"},
          { inline_data: {
              mime_type: "image/png",
              data: base64Data
            }}
          ]}
        ]
      };

  const geminiURL=`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${process.env.GEMINI_API_KEY}`;

  const response = await fetch(geminiURL, {
    method: 'post',
    body: JSON.stringify(body),
    headers: {'Content-Type': 'application/json'}
  });
  const result = await response.json();
 
  // Gemini Flash generative api returns an array of 'candidates'
  if (result.candidates && result.candidates.length) {
    const candidate = result.candidates[0];
    if (candidate.content && candidate.content['parts'] && candidate.content['parts'].length) {
      const description = candidate.content.parts[0]['text'];
      console.log(description);
      return description;
    }
  }

  return "Could not analyse image";

}


app.get('/', async (req, res) => {  
  res.json({ message: "This API expects a POST request with a base64 encoded dataURL in the imageURL property" });
})


app.post('/', async (req, res) => {  
  let result = await analyseImage(req.body['imageURL']);
  res.json({ description: result });
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})

