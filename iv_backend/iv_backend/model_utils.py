import joblib
import os
from django.conf import settings
import numpy as np

# Path to the model file
MODEL_PATH = os.path.join(settings.BASE_DIR, 'models', 'isolation_forest_model.pkl')
# MODEL_PATH12 = os.path.join(settings.BASE_DIR, 'models', 'mlp_model.pkl')

# # Function to load the model
def load_model():
    model = joblib.load(MODEL_PATH)
    return model

# def load_model1():
#     model1 = joblib.load(MODEL_PATH12)
#     return model1

# # Function to make predictions
def predict(model, input_data):
    # Perform prediction (assuming the input data is preprocessed properly)
    return model.predict([input_data]).tolist()  # Convert to list if needed

# def predict1(model1, features):
#     new_data = np.array([features])
#     print(features)
#     prediction = model1.predict(new_data)
#     return prediction[0]