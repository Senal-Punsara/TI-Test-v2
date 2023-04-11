import pandas as pd
from flask import Flask,request
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

def navieBiasModel(text):
    df = pd.read_csv("./ti/ML_filtering/dataSet.csv")
    df['label'] = df['v1'].astype('str')
    df['message'] = df['v2'].astype('str')
    df.drop(labels=['v1', 'v2'],axis=1, inplace=True)
    from sklearn.model_selection import  train_test_split
    X_train, X_test, y_train, y_test = train_test_split(df.message,df.label,test_size=0.3)
    vectorizer = TfidfVectorizer()
    X_train = vectorizer.fit_transform(X_train)
    X_test = vectorizer.transform(X_test)
    model = MultinomialNB()
    model.fit(X_train,y_train)
    model.score(X_test,y_test)
    model.predict_proba(X_test[0:1])
    predictions = model.predict(X_test)
    from sklearn.metrics import accuracy_score, precision_score, recall_score
    predictions = model.predict(X_test)
    print('Accuracy: ', accuracy_score(y_test,predictions))
    print('Precision: ', precision_score(y_test,predictions,pos_label='ham'))
    print('Recall: ', recall_score(y_test,predictions,pos_label='ham'))
    def classifyText(arr):
      return model.predict(vectorizer.transform(arr))
    messages = []
    messages.append(text)
    print(classifyText(messages)[0])
    return str(classifyText(messages)[0])

prediction = navieBiasModel("'Free entry in 2 a wkly comp to win FA Cup final tkts 21st May 2005. Text FA to 87121 to receive entry question(std txt rate)T&C's apply 08452810075over18's'")
print(prediction)