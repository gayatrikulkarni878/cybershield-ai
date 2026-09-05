// Client-side QR Code Decoder helper using Canvas and jsQR
import jsQR from 'jsqr';
import { analyzeUrlLocal } from './detectorEngine.js';

export function decodeQrImageClient(file) {
  return new Promise((resolve) => {
    if (!file) {
      resolve({
        error: "No file selected.",
        decoded_content: null,
        is_url: false,
        risk_score: 0,
        risk_level: "SAFE",
        threat_type: "None",
        indicators: [],
        explanation: "No QR file provided.",
        recommendation: "Please upload a valid image file."
      });
      return;
    }

    const reader = new FileReader();
    reader.onload = (event) => {
      const img = new Image();
      img.onload = () => {
        const canvas = document.createElement('canvas');
        const context = canvas.getContext('2d');
        canvas.width = img.width;
        canvas.height = img.height;
        context.drawImage(img, 0, 0, img.width, img.height);
        
        try {
          const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
          const code = jsQR(imageData.data, imageData.width, imageData.height, {
            inversionAttempts: "dontInvert",
          });

          if (code && code.data) {
            const decodedText = code.data.trim();
            const isUrl = /^(https?:\/\/|www\.)/i.test(decodedText);

            if (isUrl) {
              const urlAnalysis = analyzeUrlLocal(decodedText);
              resolve({
                success: true,
                decoded_content: decodedText,
                is_url: true,
                risk_score: urlAnalysis.risk_score,
                risk_level: urlAnalysis.risk_level,
                threat_type: `QR Payload: ${urlAnalysis.threat_type}`,
                indicators: [
                  {
                    code: "QR_URL_PAYLOAD",
                    title: "QR Code Contains Web Link",
                    points: 5,
                    category: "Vector Analysis",
                    description: `Decoded QR code redirects to web address: ${decodedText}`
                  },
                  ...urlAnalysis.indicators
                ],
                explanation: `Decoded QR payload: '${decodedText}'. ${urlAnalysis.explanation}`,
                recommendation: urlAnalysis.recommendation,
                url_analysis: urlAnalysis
              });
            } else {
              resolve({
                success: true,
                decoded_content: decodedText,
                is_url: false,
                risk_score: /password|pin|otp/i.test(decodedText) ? 10 : 0,
                risk_level: /password|pin|otp/i.test(decodedText) ? "LOW" : "SAFE",
                threat_type: "Plain Text QR Payload",
                indicators: [
                  {
                    code: "QR_TEXT_PAYLOAD",
                    title: "Plain Data Payload",
                    points: 0,
                    category: "Content",
                    description: `Extracted QR content: '${decodedText.slice(0, 50)}...'`
                  }
                ],
                explanation: `Decoded QR payload: '${decodedText}'. No automatic executable web redirects found.`,
                recommendation: "Review the decoded text before sharing or executing actions."
              });
            }
          } else {
            resolve({
              success: false,
              decoded_content: null,
              is_url: false,
              risk_score: 0,
              risk_level: "SAFE",
              threat_type: "No QR Code Found",
              indicators: [
                {
                  code: "NO_QR_FOUND",
                  title: "Unreadable or Missing QR Pattern",
                  points: 0,
                  category: "Scanner Alert",
                  description: "Could not locate a clear QR matrix pattern in this image."
                }
              ],
              explanation: "No QR code could be extracted from the uploaded image. Please ensure the QR code is centered and well-lit.",
              recommendation: "Upload a clearer image or use one of the quick DEMO QR sample buttons."
            });
          }
        } catch (err) {
          resolve({
            success: false,
            decoded_content: null,
            is_url: false,
            risk_score: 0,
            risk_level: "SAFE",
            threat_type: "Decoding Error",
            indicators: [],
            explanation: `Image processing error: ${err.message}`,
            recommendation: "Try another image file format (PNG, JPG)."
          });
        }
      };
      img.onerror = () => {
        resolve({
          error: "Failed to load image.",
          risk_score: 0,
          risk_level: "SAFE",
          threat_type: "None",
          indicators: [],
          explanation: "Invalid image file format.",
          recommendation: "Please upload a valid PNG or JPG file."
        });
      };
      img.src = event.target.result;
    };
    reader.readAsDataURL(file);
  });
}
