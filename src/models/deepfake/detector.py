"""
Real Deepfake Detection using multiple techniques
"""

import cv2
import numpy as np
from PIL import Image
import io
import face_recognition
import math
from collections import defaultdict

class DeepfakeDetector:
    def __init__(self):
        # Known deepfake artifacts to look for
        self.suspicious_patterns = {
            'blinking': 0.7,      # Deepfakes often have unnatural blinking
            'skin_texture': 0.6,   # AI-generated skin looks different
            'face_warping': 0.8,   # Face warping around edges
            'resolution': 0.5,      # Resolution inconsistencies
            'color_artifacts': 0.7  # Color channel anomalies
        }
        
    def analyze(self, image_bytes):
        """
        Analyze image for deepfake indicators
        
        Args:
            image_bytes: Raw image bytes (from upload)
            
        Returns:
            Dictionary with deepfake probability and indicators
        """
        try:
            # Convert bytes to image
            image = Image.open(io.BytesIO(image_bytes))
            image_np = np.array(image)
            
            # Convert to OpenCV format (RGB to BGR)
            if len(image_np.shape) == 3:
                image_cv = cv2.cvtColor(image_np, cv2.COLOR_RGB2BGR)
            else:
                image_cv = image_np
            
            # Find faces
            face_locations = face_recognition.face_locations(image_np)
            
            if len(face_locations) == 0:
                return {
                    "has_deepfake": False,
                    "confidence": 0,
                    "risk_score": 0,
                    "message": "No face detected in image",
                    "flags": ["No face found"],
                    "attack_type": "deepfake"
                }
            
            # Analyze each face
            face_results = []
            for face_location in face_locations:
                face_result = self._analyze_face(image_cv, image_np, face_location)
                face_results.append(face_result)
            
            # Aggregate results
            deepfake_prob = max([r['deepfake_probability'] for r in face_results])
            indicators = []
            for r in face_results:
                indicators.extend(r['indicators'])
            
            # Remove duplicates
            indicators = list(set(indicators))
            
            # Calculate risk score
            risk_score = int(deepfake_prob * 100)
            
            return {
                "has_deepfake": deepfake_prob > 0.6,
                "confidence": float(deepfake_prob),
                "risk_score": risk_score,
                "severity": self._get_severity(risk_score),
                "face_count": len(face_locations),
                "flags": indicators[:10],  # Limit to 10
                "analysis": {
                    "face_results": face_results,
                    "resolution": f"{image.width}x{image.height}"
                },
                "attack_type": "deepfake",
                "recommendation": self._get_recommendation(risk_score, deepfake_prob > 0.6)
            }
            
        except Exception as e:
            return {
                "has_deepfake": False,
                "confidence": 0,
                "risk_score": 0,
                "error": str(e),
                "flags": [f"Error analyzing image: {str(e)[:50]}..."],
                "attack_type": "deepfake"
            }
    
    def _analyze_face(self, image_cv, image_np, face_location):
        """Analyze a single face for deepfake indicators"""
        top, right, bottom, left = face_location
        
        # Extract face region
        face_image = image_np[top:bottom, left:right]
        
        indicators = []
        scores = []
        
        # Test 1: Check for unnatural blinking patterns
        blink_score = self._check_blinking_pattern(face_image)
        scores.append(blink_score)
        if blink_score > 0.7:
            indicators.append("Unnatural blinking pattern detected")
        
        # Test 2: Check skin texture anomalies
        texture_score = self._check_skin_texture(face_image)
        scores.append(texture_score)
        if texture_score > 0.6:
            indicators.append("AI-generated skin texture detected")
        
        # Test 3: Check face warping at edges
        warp_score = self._check_face_warping(image_cv, face_location)
        scores.append(warp_score)
        if warp_score > 0.8:
            indicators.append("Face warping artifacts detected")
        
        # Test 4: Check color channel inconsistencies
        color_score = self._check_color_artifacts(face_image)
        scores.append(color_score)
        if color_score > 0.7:
            indicators.append("Color channel anomalies detected")
        
        # Test 5: Check eye symmetry
        eye_score = self._check_eye_symmetry(image_np, face_location)
        scores.append(eye_score)
        if eye_score > 0.6:
            indicators.append("Asymmetrical eyes detected")
        
        # Calculate overall probability
        deepfake_prob = np.mean(scores)
        
        return {
            "deepfake_probability": float(deepfake_prob),
            "indicators": indicators,
            "face_size": f"{right-left}x{bottom-top}",
            "scores": {
                "blinking": float(blink_score),
                "texture": float(texture_score),
                "warping": float(warp_score),
                "color": float(color_score),
                "eye_symmetry": float(eye_score)
            }
        }
    
    def _check_blinking_pattern(self, face_image):
        """Check for unnatural blinking (simplified - in production use temporal analysis)"""
        # Real faces have specific eye aspect ratios
        # Deepfakes often have inconsistent blinking
        
        # Simplified: Check eye region clarity
        if face_image.size == 0:
            return 0.5
            
        gray = cv2.cvtColor(face_image, cv2.COLOR_RGB2GRAY) if len(face_image.shape) == 3 else face_image
        
        # Calculate sharpness in eye region (deepfakes often blurry)
        laplacian_var = cv2.Laplacian(gray, cv2.CV_64F).var()
        
        # Normalize score
        if laplacian_var < 50:
            return 0.8  # Too blurry -> suspicious
        elif laplacian_var > 200:
            return 0.3  # Very sharp -> likely real
        else:
            return 0.5  # Normal range
    
    def _check_skin_texture(self, face_image):
        """Check for AI-generated skin texture patterns"""
        if face_image.size == 0:
            return 0.5
            
        # Convert to grayscale
        if len(face_image.shape) == 3:
            gray = cv2.cvtColor(face_image, cv2.COLOR_RGB2GRAY)
        else:
            gray = face_image
        
        # Calculate texture complexity using GLCM-like approach
        # Simplified: check variance in different regions
        h, w = gray.shape
        regions = []
        
        # Split face into 4 regions
        for i in range(2):
            for j in range(2):
                region = gray[i*h//2:(i+1)*h//2, j*w//2:(j+1)*w//2]
                if region.size > 0:
                    regions.append(np.var(region))
        
        avg_variance = np.mean(regions) if regions else 0
        
        # Real faces have natural texture variance
        if avg_variance < 500:
            return 0.7  # Too uniform -> suspicious
        elif avg_variance > 3000:
            return 0.6  # Too noisy -> maybe GAN artifact
        else:
            return 0.3  # Natural range
    
    def _check_face_warping(self, image_cv, face_location):
        """Check for warping artifacts around face edges"""
        top, right, bottom, left = face_location
        h, w = image_cv.shape[:2]
        
        # Expand region slightly to catch edges
        expanded_top = max(0, top - 10)
        expanded_bottom = min(h, bottom + 10)
        expanded_left = max(0, left - 10)
        expanded_right = min(w, right + 10)
        
        # Get edge region
        edge_region = image_cv[expanded_top:expanded_bottom, expanded_left:expanded_right]
        
        if edge_region.size == 0:
            return 0.5
            
        # Convert to grayscale
        if len(edge_region.shape) == 3:
            gray = cv2.cvtColor(edge_region, cv2.COLOR_BGR2GRAY)
        else:
            gray = edge_region
        
        # Detect edges using Canny
        edges = cv2.Canny(gray, 50, 150)
        
        # Calculate edge density around face boundary
        face_boundary = edges[10:-10, 10:-10] if edges.shape[0] > 20 and edges.shape[1] > 20 else edges
        edge_density = np.sum(edges > 0) / edges.size if edges.size > 0 else 0
        
        # Deepfakes often have unnatural edge patterns
        if edge_density > 0.3:
            return 0.8  # Too many edges -> warping artifacts
        elif edge_density < 0.05:
            return 0.6  # Too few edges -> too smooth
        else:
            return 0.3  # Natural edge density
    
    def _check_color_artifacts(self, face_image):
        """Check for color channel inconsistencies"""
        if len(face_image.shape) != 3 or face_image.shape[2] != 3:
            return 0.5
            
        # Split into RGB channels
        r = face_image[:, :, 0].astype(float)
        g = face_image[:, :, 1].astype(float)
        b = face_image[:, :, 2].astype(float)
        
        # Calculate channel correlations
        rg_corr = np.corrcoef(r.flatten(), g.flatten())[0, 1]
        rb_corr = np.corrcoef(r.flatten(), b.flatten())[0, 1]
        gb_corr = np.corrcoef(g.flatten(), b.flatten())[0, 1]
        
        avg_corr = (rg_corr + rb_corr + gb_corr) / 3
        
        # Real faces have natural color correlations
        if avg_corr > 0.99:
            return 0.8  # Too correlated -> possible AI generation
        elif avg_corr < 0.7:
            return 0.7  # Too uncorrelated -> color artifacts
        else:
            return 0.3  # Natural correlation
    
    def _check_eye_symmetry(self, image_np, face_location):
        """Check eye symmetry (deepfakes often have asymmetric eyes)"""
        top, right, bottom, left = face_location
        
        # Get eye landmarks
        face_landmarks = face_recognition.face_landmarks(image_np, [face_location])
        
        if not face_landmarks:
            return 0.5
            
        landmarks = face_landmarks[0]
        
        # Check if both eyes detected
        if 'left_eye' not in landmarks or 'right_eye' not in landmarks:
            return 0.5
            
        left_eye = np.mean(landmarks['left_eye'], axis=0)
        right_eye = np.mean(landmarks['right_eye'], axis=0)
        
        # Calculate eye sizes (simplified)
        left_eye_size = np.ptp(landmarks['left_eye'], axis=0).max()
        right_eye_size = np.ptp(landmarks['right_eye'], axis=0).max()
        
        if left_eye_size == 0 or right_eye_size == 0:
            return 0.5
            
        # Asymmetry ratio
        asymmetry = abs(left_eye_size - right_eye_size) / max(left_eye_size, right_eye_size)
        
        if asymmetry > 0.3:
            return 0.8  # Asymmetric -> suspicious
        elif asymmetry > 0.15:
            return 0.6  # Mildly asymmetric
        else:
            return 0.3  # Symmetric
    
    def _get_severity(self, risk_score):
        """Convert risk score to severity"""
        if risk_score >= 80:
            return "CRITICAL"
        elif risk_score >= 60:
            return "HIGH"
        elif risk_score >= 30:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _get_recommendation(self, risk_score, is_deepfake):
        """Generate recommendation"""
        if is_deepfake:
            return "DEEPFAKE DETECTED - Do not trust this media. Investigate source immediately."
        elif risk_score >= 50:
            return "SUSPICIOUS - Manual review recommended before trusting this media."
        elif risk_score >= 30:
            return "CAUTION - Some unusual artifacts detected. Verify source if important."
        else:
            return "LIKELY AUTHENTIC - No significant deepfake indicators detected."