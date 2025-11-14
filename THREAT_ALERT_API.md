# Threat Alert API Documentation

## Overview
The backend now sends a threat alert command to the frontend when a **confirmed threat** is detected (not just images with possible threats).

## API Response Format

When an image is analyzed, the backend returns a JSON response with the following structure:

```json
{
  "description": "string - Description of what was found in the image",
  "hasThreat": boolean - Indicates if a confirmed threat was detected,
  "isThreat": boolean - Alternative flag name for frontend compatibility,
  "alert": boolean - Another flag indicating threat status,
  "command": {
    "type": "THREAT_ALERT",
    "action": "activate_audio_alert",
    "severity": "high",
    "message": "Threat detected. Activating audio alert."
  }
}
```

## When Command is Sent

The `command` object **only** appears in the response when:
- `hasThreat === true` (a confirmed threat was detected)
- NOT for images with possible threats or uncertain threats

## Frontend Implementation

The frontend should check for the command property and respond accordingly:

```javascript
fetch('http://localhost:3000', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ imageURL: dataURL })
})
.then(response => response.json())
.then(data => {
  console.log('Analysis result:', data);
  
  // Check for threat alert command
  if (data.command && data.command.type === 'THREAT_ALERT') {
    // Activate audio alert
    activateThreatAudio();
  }
});
```

## Audio Alert Implementation Example

```javascript
function activateThreatAudio() {
  // Option 1: Use Web Audio API to generate a tone
  const audioContext = new (window.AudioContext || window.webkitAudioContext)();
  const oscillator = audioContext.createOscillator();
  const gainNode = audioContext.createGain();
  
  oscillator.connect(gainNode);
  gainNode.connect(audioContext.destination);
  
  oscillator.frequency.value = 800; // Hz
  oscillator.type = 'sine';
  
  gainNode.gain.setValueAtTime(0.3, audioContext.currentTime);
  gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.5);
  
  oscillator.start(audioContext.currentTime);
  oscillator.stop(audioContext.currentTime + 0.5);
  
  // Option 2: Play a pre-recorded alert sound
  // const alertSound = new Audio('./sounds/threat-alert.mp3');
  // alertSound.play();
}
```

## Threat Detection Logic

The backend uses strict threat detection logic:

1. **Negation Check**: If the model says "no threat", "not dangerous", etc., it's ignored
2. **Strong Keywords**: Weapons, explosives, violence → immediate threat flag
3. **Weak Keywords with Certainty**: "threat", "danger", "suspicious" only flag if accompanied by certainty words like "detected", "confirmed", "likely"

This ensures only confirmed threats trigger the audio alert, not uncertain or false positives.
