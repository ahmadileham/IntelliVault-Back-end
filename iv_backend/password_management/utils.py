import numpy as np
from sklearn.preprocessing import StandardScaler
import joblib
from pathlib import Path

class PasswordSimilarityChecker:
    def __init__(self):
        """Initialize the checker with a pre-trained model."""
        # Load the model and scaler
        model_path = 'resources/model3.pkl'
        model_data = joblib.load(model_path)
        self.clustering = model_data['clustering']
        self.scaler = model_data['scaler']
        self.X_scaled = model_data['X_scaled']

        
    def get_char_type(self, char):
        """Classify character into type categories."""
        common_lower = 'esaitnruol'
        common_upper = 'ESAITNRUOL'
        numbers = '0123456789'
        common_special = '><-?.!/,%@&'
        
        if char in common_lower:
            return '1'
        elif char.islower():
            return '2'
        elif char in common_upper:
            return '3'
        elif char.isupper():
            return '4'
        elif char in numbers:
            return '5'
        elif char in common_special:
            return '6'
        elif not char.isalnum():
            return '7'
        else:
            return '0'

    def mask_password(self, password):
        """Convert password to masked version."""
        return ''.join(self.get_char_type(c) for c in str(password))

    def create_features(self, masked_pass):
        """Create feature matrix from masked password."""
        max_len = 30
        X = np.zeros((len(masked_pass), max_len))
        
        for i, password in enumerate(masked_pass):
            padded = password.ljust(max_len, '0')
            for j, char in enumerate(padded[:max_len]):
                X[i, j] = int(char)
        
        return X

    def calculate_similarity(self, password):
        """
        Compute similarity percentage between input password and breached password clusters.
        
        Parameters:
        -----------
        password : str
            Input password to check
        clustering : AgglomerativeClustering
            Fitted clustering model
        X_scaled : array
            Scaled feature matrix used for clustering
        scaler : StandardScaler
            Fitted scaler used to transform features
            
        Returns:
        --------
        float
            Similarity percentage (0-100)
        int
            Most similar cluster ID
        """
        scaler = self.scaler
        clustering = self.clustering
        X_scaled = self.X_scaled
        # Convert password to masked version
        masked_pwd = self.mask_password(password)
        
        # Create features for the single password
        X_new = self.create_features([masked_pwd])
        
        # Scale the features using the same scaler
        X_new_scaled = scaler.transform(X_new)
        
        # Calculate distances to all cluster centers
        distances = []
        for i in range(clustering.n_clusters_):
            mask = clustering.labels_ == i
            center = np.mean(X_scaled[mask], axis=0)
            dist = np.linalg.norm(X_new_scaled - center)
            distances.append(dist)
        
        # Convert distance to similarity percentage
        min_dist = min(distances)
        closest_cluster = np.argmin(distances)
        
        # Use a steeper exponential decay with normalization
        max_reasonable_dist = 10.0  # You may need to adjust this based on your data
        normalized_dist = min_dist / max_reasonable_dist
        similarity = 100 * np.exp(-2 * normalized_dist)  # Steeper decay with factor -2
        
        # Clip to ensure we don't exceed 100%
        similarity = min(similarity, 100.0)
        
        return similarity