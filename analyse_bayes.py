from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer, HashingVectorizer
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.linear_model import SGDClassifier
from lib import *
import numpy as np
import os


'''
configuration
'''

trainingCount = 60

baseDir = '../CVE-directories'
trainingDataCSV = '../training.csv'
evaluationFile = 'evaluationtable.csv'

categories = [
    "Bufferoverflow",
    "Memory leak",
    "Network",
    "Others"
]

createBoWElementFunctions = [
    createBagOfWordsElementFromCode,
    createBagOfWordsElementFromNote,
    createBagOfWordsElementFromBoth
]

vectorizers = [
    CountVectorizer,
    TfidfVectorizer,
    HashingVectorizer
]

regexOptions = [
#    u'(?u)\b\w\w+\b',
    u'([^\s]+)\s*',
    u'([a-zA-Z]+)\s*'
]


'''
start code execution
'''

# pull training data
trainingData, trainingTargets, trainingLabels = getData(trainingDataCSV)

visitedTargets = [];
bagOfWordsInputData = []


for i in range(len(createBoWElementFunctions)):
    bagOfWordsInputData.append([])


# loop cve directories
for dirname in os.listdir(baseDir):
    cveID = dirname
    cveDir = os.path.join(baseDir, dirname)
    i = 0


    # check cve directories only
    if dirname[:4] != 'CVE-' or not os.path.isdir(cveDir):
        continue


    try:
        dataIndex = trainingLabels.index(cveID)
    except Exception as e:
        # skip files which are not in training or testdata
        continue


    visitedTargets.append(trainingTargets[dataIndex])


    commitFile = os.path.join(cveDir, 'commit')
    noteFile = os.path.join(cveDir, 'note')

    # commit file AND commit note must exits otherwise ignore cve
    if os.path.isfile(commitFile) == False or os.path.isfile(noteFile) == False:
        print "[SKIP]insufficient", cveDir
        continue


    print '[OKAY]', cveDir

    # loop all BoW data functions to create BoW data for each function
    for createBoWElementFn in createBoWElementFunctions:
        element = createBoWElementFn(cveDir)

        bagOfWordsInputData[i].append(element)
        i = i + 1;


'''
start bayes evaluation
'''


evaluationRows = [None] * ((len(vectorizers) * len(regexOptions) * len(bagOfWordsInputData) * 2) + 1)
evaluationRows[0] = ['Vectorizer', 'Transformer', 'Regex', 'Input Data Type', 'Precision', 'Recall']
k = 1

for r in regexOptions:

    for vectorizer in vectorizers:
        i = 0

        if vectorizer.__name__ == 'HashingVectorizer':
            v = vectorizer(token_pattern=r, non_negative=True)
        else:
            v = vectorizer(token_pattern=r)


        bayesTfidf = Pipeline([
            ('vect', v),
            ('tfidf', TfidfTransformer()),
            ('clf', MultinomialNB())
        ])

        bayes = Pipeline([
            ('vect', v),
            ('clf', MultinomialNB())
        ])


        # pass training data initially to the machine learning instances
        bayesTfidf = bayesTfidf.fit(trainingData[:trainingCount], trainingTargets[:trainingCount])
        bayes = bayes.fit(trainingData[:trainingCount], trainingTargets[:trainingCount])


        for data in bagOfWordsInputData:

            predictedBayesTfidf = bayesTfidf.predict(data)
            predictedBayes = bayes.predict(data)

            resultTfidf = evaluateBayes(predictedBayesTfidf, visitedTargets, categories, False)
            result = evaluateBayes(predictedBayes, visitedTargets, categories, False)


            evaluationRows[k] = [
                vectorizer.__name__,
                '-',
                r,
                createBoWElementFunctions[i].__name__,
                result[0],
                result[1]
            ]

            evaluationRows[k+1] = [
                vectorizer.__name__,
                'Tfidf',
                r,
                createBoWElementFunctions[i].__name__,
                resultTfidf[0],
                resultTfidf[1]
            ]

            print evaluationRows[k]
            print evaluationRows[k+1]
            line()

            k = k + 2
            i = i + 1

#save evaluation results as file
with open(evaluationFile, 'wb') as csvfile:
    writer = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

    for value in evaluationRows:
        writer.writerow(value)
