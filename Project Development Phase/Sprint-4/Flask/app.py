from flask import Flask, render_template,request,jsonify
import pickle
import inputScript
import numpy as np
app = Flask(__name__)
loaded_model = pickle.load(open("Phishing_Website.pkl", 'rb'))
@app.route('/')
def home():
   return render_template('index.html')

@app.route('/final')
def  final():
    
    return render_template("final.html")

@app.route('/y_predict',methods=['POST'])
def y_predict():
    
    
    url = request.form['URL']
    checkprediction = inputScript.main(url)
    prediction =loaded_model.predict(checkprediction)
    print(prediction) 
    output=prediction[0]
    if(output==1):
        pred="Your are safe!!  This is a Legitimate Website."
    else:
        pred="Your are on the wrong site. Be cautious!"
    return render_template('final.html', prediction_text='{}'.format(pred),url=url)
    
@app.route('/predict_api',methods=['POST'])
def predict_api():
    '''
    For direct API calls trought request
    '''
    data = request.get_json(force=True)
    prediction = loaded_model.y_predict([np.array(list(data.values()))])

    output = prediction[0]
    return jsonify(output)
if __name__ == '__main__':
   app.run()

   '''
import numpy as np
from flask import Flask,request,jsonify,render_template
import pickle
#importing the inputScript file used to analyze the URL
import inputScript

#load model
app = Flask(__name__)
model=pickle.load(open('Phishing_Websites.pkl','rb'))

#fetches the URL given by the URL and passes to inputScript

    
#Takes the input parameters fetched from the URL by inputsScript and returns the 


if __name__ =='__main__':
    app.run(host='0.0.0.0', debug=True)
'''