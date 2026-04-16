import pickle

with open('pickle_files/chatgpt_bidirectional_pkl_random_forest.pkl', 'rb') as f:
    data = pickle.load(f)

print(f"Type: {type(data)}")
if isinstance(data, dict):
    print(f"Keys: {data.keys()}")
elif hasattr(data, 'head'):
    print("This looks like a DataFrame (Data)")
    print(data.head())
else:
    print("This looks like a Model object")