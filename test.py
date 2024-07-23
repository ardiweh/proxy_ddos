import pickle

try:
    with open('pca.pkl', 'rb') as file:
        pca = pickle.load(file)
    print("Model loaded successfully with pickle")
except Exception as e:
    print(f"Failed to load model with pickle: {e}")
