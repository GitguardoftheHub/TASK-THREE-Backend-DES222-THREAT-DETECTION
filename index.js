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
          { text: "Is there a threat in this image? If so, what is the threat and describe it."},
          { inline_data: {
              mime_type: "image/png",
              data: base64Data
            }}
          ]}
        ]
      };

  const geminiURL=`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${process.env.SECRET_GOOGLE_GEMINI_KEY}`;

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


// Helper: interpret boolean-like values returned from other systems
function parseBooleanLike(val) {
  if (typeof val === 'boolean') return val;
  if (typeof val === 'number') return val !== 0;
  if (!val) return false;
  const s = String(val).toLowerCase().trim();
  return ['true', 'yes', '1', 'y'].includes(s);
}

// Helper: stricter, negation-aware threat detection from free-form description text
function isThreatDescription(text) {
  if (!text) return false;
  const lower = String(text).toLowerCase();

  // If the model explicitly negates a threat ("no threat", "not a threat", "not dangerous"), do not flag
  const negationRegex = /\b(no|not|none|without|never|unlikely|n't)\b(?:(?:\s+\w+){0,6})\s*\b(threat|danger|weapon|gun|knife|bomb|explosive|attack|violence|shooting|stabbing|hostage)\b/;
  if (negationRegex.test(lower)) return false;

  // Strong keywords — immediate trigger
  const strongRegex = /\b(weapon|gun|knife|bomb|explosive|rifle|pistol|shooting|stabbing|hostage|explosion|grenade|shooter)\b/;
  if (strongRegex.test(lower)) return true;

  // Weak keywords require an accompanying certainty/detection verb to avoid false positives
  const weakRegex = /\b(threat|danger|risk|suspicious|hazard|unsafe)\b/;
  // expanded certainty words to include softer phrasing often used by models
  const certaintyRegex = /\b(detected|detected a|detected an|confirmed|likely|possible|probable|suspected|observed|identified|found|appears?|seems?|may|might|possibly|indicat(?:es|ing)?|suggest(?:s|ing)?|looks?)\b/;
  if (weakRegex.test(lower) && certaintyRegex.test(lower)) return true;

  return false;
}

app.post('/', async (req, res) => {  
  const imageURL = req.body && req.body['imageURL'];
  let result = await analyseImage(imageURL);
  const description = result || "Could not analyse image";

  // Final decision: prefer any explicit boolean-like flags from upstream (if present),
  // otherwise use the stricter textual analysis.
  // Note: Gemini here returns only text, but this keeps compatibility if flags are added later.
  let hasThreat = false;
  try {
    // If the analyseImage implementation is changed to return a structured object in future,
    // handle that gracefully.
    if (typeof result === 'object' && result !== null) {
      // check known flag names
      const possibleFlags = ['hasThreat', 'isThreat', 'alert', 'threat', 'danger'];
      for (const f of possibleFlags) {
        if (Object.prototype.hasOwnProperty.call(result, f)) {
          hasThreat = parseBooleanLike(result[f]);
          if (hasThreat) break;
        }
      }
      // if description is present in the object, prefer textual analysis when flags are absent/false
      if (!hasThreat && result.description) {
        hasThreat = isThreatDescription(result.description);
      }
    } else {
      hasThreat = isThreatDescription(description);
    }
  } catch (err) {
    // fallback: do not trigger alarm on unexpected errors while parsing
    console.error('Threat detection error:', err);
    hasThreat = false;
  }

  const response = {
    description: description,
    hasThreat: hasThreat,
    isThreat: hasThreat,  // alternative flag name for frontend compatibility
    alert: hasThreat
  };

  // If a threat is detected, send command to activate audio alert on frontend
  if (hasThreat) {
    response.command = {
      type: 'THREAT_ALERT',
      action: 'activate_audio_alert',
      severity: 'high',
      message: 'Threat detected. Activating audio alert.'
    };
  }

  res.json(response);
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})

