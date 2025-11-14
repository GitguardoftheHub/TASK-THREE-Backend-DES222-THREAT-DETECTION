/**
 * Threat Alert Audio Handler
 * 
 * This module provides utilities for handling threat alert audio signals
 * from the backend threat detection API.
 * 
 * Usage:
 *   - Call handleThreatAlert(apiResponse) with the response from the backend
 *   - Or manually use activateThreatAudio() for direct audio control
 */

class ThreatAlertHandler {
  constructor() {
    this.audioContext = null;
    this.isAudioInitialized = false;
  }

  /**
   * Initialize Web Audio API context
   * Call this on user interaction (click, tap) due to browser autoplay restrictions
   */
  initializeAudioContext() {
    if (!this.isAudioInitialized) {
      try {
        this.audioContext = new (window.AudioContext || window.webkitAudioContext)();
        this.isAudioInitialized = true;
        console.log('Audio context initialized');
      } catch (err) {
        console.warn('Web Audio API not supported:', err);
      }
    }
  }

  /**
   * Activate threat alert audio signal
   * Generates a 0.5 second alarm tone at 800Hz
   * 
   * @param {number} frequency - Frequency in Hz (default: 800)
   * @param {number} duration - Duration in seconds (default: 0.5)
   * @param {number} volume - Volume from 0 to 1 (default: 0.3)
   */
  activateThreatAudio(frequency = 800, duration = 0.5, volume = 0.3) {
    if (!this.isAudioInitialized || !this.audioContext) {
      console.warn('Audio context not initialized. Call initializeAudioContext() first.');
      return;
    }

    try {
      const oscillator = this.audioContext.createOscillator();
      const gainNode = this.audioContext.createGain();

      oscillator.connect(gainNode);
      gainNode.connect(this.audioContext.destination);

      oscillator.frequency.value = frequency;
      oscillator.type = 'sine';

      const now = this.audioContext.currentTime;
      gainNode.gain.setValueAtTime(volume, now);
      gainNode.gain.exponentialRampToValueAtTime(0.01, now + duration);

      oscillator.start(now);
      oscillator.stop(now + duration);

      console.log('Threat audio alert activated');
    } catch (err) {
      console.error('Error generating threat audio:', err);
    }
  }

  /**
   * Play a pre-recorded threat alert sound
   * 
   * @param {string} soundPath - Path to the audio file (mp3, wav, etc.)
   */
  playAlertSound(soundPath) {
    try {
      const audio = new Audio(soundPath);
      audio.volume = 0.5;
      audio.play().catch(err => {
        console.error('Error playing alert sound:', err);
      });
      console.log('Playing alert sound:', soundPath);
    } catch (err) {
      console.error('Error creating audio element:', err);
    }
  }

  /**
   * Handle response from the threat detection API
   * Automatically activates audio alert if threat is detected
   * 
   * @param {object} apiResponse - Response object from backend POST /
   * @returns {boolean} true if threat was detected and alert activated
   */
  handleThreatAlert(apiResponse) {
    if (!apiResponse) {
      console.warn('Invalid API response');
      return false;
    }

    // Check if the response contains a threat alert command
    if (apiResponse.command && apiResponse.command.type === 'THREAT_ALERT') {
      console.log('🚨 THREAT DETECTED:', apiResponse.command.message);
      console.log('Threat description:', apiResponse.description);

      // Activate the audio alert
      this.activateThreatAudio();

      return true;
    }

    // Also check the hasThreat/alert flags as fallback
    if (apiResponse.hasThreat || apiResponse.isThreat || apiResponse.alert) {
      console.log('⚠️ Potential threat detected (no command):', apiResponse.description);
      // Optionally activate audio here if you want to alert on all threats
      // this.activateThreatAudio();
      return true;
    }

    console.log('✓ No threat detected');
    return false;
  }

  /**
   * Convenience method to activate audio alert on user action
   * Ensures audio context is ready and activates threat audio
   * Call this on button click, etc.
   */
  activateOnUserAction() {
    this.initializeAudioContext();
    this.activateThreatAudio();
  }
}

// Export as singleton
const threatAlertHandler = new ThreatAlertHandler();

// Also export the class for multiple instances if needed
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { ThreatAlertHandler, threatAlertHandler };
}
