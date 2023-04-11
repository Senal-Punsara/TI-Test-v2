import pandas as pd
from flask import Flask,request
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import  train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score
from flasgger import Swagger
app = Flask(__name__)
Swagger(app)


def navieBiasModel(text):
    df = pd.read_csv("dataSet.csv")
    df['label'] = df['category'].astype('str')
    df['message'] = df['text'].astype('str')
    df.drop(labels=['category', 'text'],axis=1, inplace=True)
    X_train, X_test, y_train, y_test = train_test_split(df.message,df.label,test_size=0.3)
    vectorizer = TfidfVectorizer()
    X_train = vectorizer.fit_transform(X_train)
    X_test = vectorizer.transform(X_test)
    model = MultinomialNB()
    model.fit(X_train,y_train)
    model.score(X_test,y_test)
    model.predict_proba(X_test[0:1])
    predictions = model.predict(X_test)
    predictions = model.predict(X_test)
    print('Accuracy: ', accuracy_score(y_test,predictions))
    print('Precision: ', precision_score(y_test,predictions,pos_label='relevent'))
    print('Recall: ', recall_score(y_test,predictions,pos_label='relevent'))
    def classifyText(arr):
      return model.predict(vectorizer.transform(arr))
    messages = []
    messages.append(text)
    print(classifyText(messages)[0])
    return str(classifyText(messages)[0])

@app.route('/')
def welcome():
    return "Machine Learning Model for filtering RSS feeds"

@app.route('/predict',methods = ['POST'])
def predict_Relevent_or_not():
    """Let's predict the feed is relevent or not
    ---
    parameters:
      - name: text
        in: query
        type: string
        required: true
      
    responses:
        200:
            description: The output values
        
    """
    text = request.args.get('text')
    prediction = navieBiasModel(text)
    return str(prediction)

if __name__ =='__main__':
    app.run(host='0.0.0.0',port=5000)

