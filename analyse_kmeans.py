from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer, HashingVectorizer
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.pipeline import make_pipeline
from sklearn.cluster import KMeans
from lib import *
import numpy as np
import os, csv


'''
@description kmeans algorithm evaluation
@author Reza Jahangiri <s6rejaha@uni-bonn.de>
'''



##########################
# configuration
##########################



# path of CVE files
baseDir = '../CVE-directories'

# path of training data
trainingDataCSV = '../training.csv'

# path of generated evaluation file
evaluationFile = 'evaluation_kmeans.csv'

# category labels
categories = [
    "Bufferoverflow",
    "Memory leak",
    "Network",
    "Others"
]

# array of bag of Words creating methods
createBoWElementFunctions = [
    createBagOfWordsElementFromCode,
    createBagOfWordsElementFromNote,
    createBagOfWordsElementFromBoth
]

# array of vectorizer methods
vectorizers = [
    CountVectorizer,
    TfidfVectorizer,
    HashingVectorizer
]

# array of regular expressions
regexOptions = [
    u'([^\s]+)\s*',
    u'([a-zA-Z]+)\s*'
]

# kmeans initialization approach (how to determine cluser centers)
kInit = 'k-means++'

# number of clusters
kClusters = 4

# maximum number of iterations for a single run
kMaxIter = 100



##########################
# start code execution
##########################



# pull training data
trainingData, trainingTargets, trainingLabels = getData(trainingDataCSV)

trainingDataIndices = []
trainingDataTargets = []
bagOfWordsInputData = []

# prepare bag of words array initially
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
        # check if CVE-ID exists in training data
        dataIndex = trainingLabels.index(cveID)

        # save current Training Target
        trainingDataTargets.append(trainingTargets[dataIndex])

        # save current index
        trainingDataIndices.append(j)

    except Exception as e:
        a = 0 # nope workaround


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



##########################
# start kmeans evaluation
##########################



# initialize the evaluation table rows
evaluationRows = [None] * ((len(vectorizers) * len(regexOptions) * len(bagOfWordsInputData) * 2) + 1)
evaluationRows[0] = ['Vectorizer', 'Transformer', 'Regex', 'Input Data Type', 'Completeness Score',
                    'Homogeneity Score', 'Adjusted Rand Score', 'Adjusted Mutual Info Score']

# append row labels for each cluster
for k in range(kClusters):
    evaluationRows[0] = evaluationRows[0] + [
        'Cluster ' + str(k) + ' - Precision',
        'Cluster ' + str(k) + ' - Recall'
    ]

k = 1

# loop regular expressions
for r in regexOptions:

    # loop vectorizer
    for vectorizer in vectorizers:
        i = 0

        # init kmeans instances

        kmeans = KMeans(n_clusters = kClusters, init = kInit, max_iter = kMaxIter)
        kmeansTfidf = KMeans(n_clusters = kClusters, init = kInit, max_iter = kMaxIter)


        if vectorizer.__name__ == 'HashingVectorizer':
            v = vectorizer(token_pattern=r, non_negative=True)

            vTfidf = make_pipeline(
                vectorizer(token_pattern=r, non_negative=True),
                TfidfTransformer()
            )
        else:
            v = vectorizer(token_pattern=r)

            vTfidf = make_pipeline(
                vectorizer(token_pattern=r),
                TfidfTransformer()
            )


        # loop bag of words input data
        for data in bagOfWordsInputData:
            trainingDataPredicted = []
            trainingDataPredictedTfidf = []
            tmp = []
            tmpTfidf = []


            # predict kmeans
            result = v.fit_transform(data)
            kmeans.fit(result)

            # predict kmeans with tfidf
            resultTfidf = vTfidf.fit_transform(data)
            kmeansTfidf.fit(resultTfidf)


            # retrieve predicted data
            predicted = kmeans.labels_
            predictedTfidf = kmeansTfidf.labels_


            # extract predicted values for testdata (evaluation prepartion)
            for n in trainingDataIndices:
                trainingDataPredicted.append(predicted[n])
                trainingDataPredictedTfidf.append(predictedTfidf[n])


            # evaluate kmeans
            result = evaluateKmeans(kmeans, trainingDataPredicted, trainingDataTargets)
            resultTfidf = evaluateKmeans(kmeansTfidf, trainingDataPredictedTfidf, trainingDataTargets)


            # prepare csv rows
            for j in range(kClusters):
                tmp = tmp + result[0][j]
                tmpTfidf = tmpTfidf + resultTfidf[0][j]


            evaluationRows[k] = [
                vectorizer.__name__,
                '-',
                r,
                createBoWElementFunctions[i].__name__,
                result[1],
                result[2],
                result[3],
                result[4]
            ] + tmp

            evaluationRows[k+1] = [
                vectorizer.__name__,
                'Tfidf',
                r,
                createBoWElementFunctions[i].__name__,
                resultTfidf[1],
                resultTfidf[2],
                resultTfidf[3],
                resultTfidf[4]
            ] + tmpTfidf

            print evaluationRows[k]
            line()

            k = k + 2
            i = i + 1

# save evaluation results as file
buildEvaluationFile(evaluationFile, evaluationRows)
