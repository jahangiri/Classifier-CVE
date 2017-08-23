from sklearn.feature_extraction.text import CountVectorizer
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.linear_model import SGDClassifier
from sklearn.cluster import KMeans
from sklearn import metrics
from lib import *
import numpy as np
import os


'''
configuration
'''

baseDir = '../CVE-directories'
trainingDataCSV = '../training.csv'

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


'''
start code execution
'''

# pull training data
trainingData, trainingTargets, trainingLabels = getData(trainingDataCSV)

trainingDataIndices = [];
trainingDataTargets = [];


#
bagOfWordsInputData = []

for i in range(len(createBoWElementFunctions)):
    bagOfWordsInputData.append([])

j = 0

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

        # save current Training Target
        trainingDataTargets.append(trainingTargets[dataIndex])

        # save current index
        trainingDataIndices.append(j)

    except Exception as e:
        a = 0 # nope

    #visitedLabels.append(trainingLabels[dataIndex])
    #visitedTargets.append(trainingTargets[dataIndex])


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

    j = j + 1


regex1 = u'([^\s]+)\s*'


k = 4 # TODO
kmeans = KMeans(n_clusters = k, init = 'k-means++', max_iter = 100)
#countVect = CountVectorizer(analyzer='word', stop_words='english', token_pattern = regex1)
countVect = CountVectorizer()


i = 0

line()

for data in bagOfWordsInputData:

    countVectResult = countVect.fit_transform(data)
    kmeans.fit(countVectResult)

    predicted = kmeans.labels_
    trainingDataPredicted = []

    for n in trainingDataIndices:
        trainingDataPredicted.append(predicted[n])


    print 'Kmeans (Count) - ARI', createBoWElementFunctions[i]
    evaluateKmeansARI2(trainingDataPredicted, trainingDataTargets)
    line()

    '''
    print 'Kmeans (Count) - own approach' , createBoWElementFunctions[i]
    evaluateKmeans(labels, targets)
    line()
    '''
    i = i + 1


    # TODO: kmeans evaluation

    #TODO Klassifzierung des BoWs mit Verfahren
    #TODO Evaluierung von Klassifzierungsergebnis
    #TODO Evaluierungsergebnis in Textdatei abspeichern


#TODO Evaluationstdatei mit allen Kombinationsmoeglichkeiten
