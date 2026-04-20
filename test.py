import joblib
import numpy as np
from utility import main
print("google.com:", main('google.com'))
print("youtube.com/watch:", main('youtube.com/watch?v=PUDOlyCpHwo'))

model = joblib.load('model.pkl')
urls = [
    'https://www.google.com',
    'http://www.google.com',
    'google.com',
    'https://youtube.com',
    'https://microsoft.com',
    'youtube.com/watch?v=PUDOlyCpHwo',
    'flixster.com/actor/steve-mcqueen',
    'https://www.google.com',
    'http://login-paypal.com/signin',
]
for url in urls:
    features = main(url)
    pred = model.predict(np.array(features).reshape(1,-1))
    label = 'SAFE' if pred[0]==0 else 'MALICIOUS'
    print(f'{label} - {url}')