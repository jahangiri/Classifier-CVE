from sklearn import metrics
import numpy as np;
import os, csv, re;


'''
@description library of functions for bayes and kmeans
@author Reza Jahangiri <s6rejaha@uni-bonn.de>
'''



##########################
# training data function
##########################



'''
Returns training data.

@param      path to csv xml file
@return     [data, targets, labels]
'''
def getData(csvFile):
    data = []
    targets = []
    labels = []

    with open(csvFile, 'rb') as csvFile:
        csvReader = csv.reader(csvFile)

        for row in csvFile.readlines():
            parts = row.split(",")

            targets.append(int(parts[0]))
            labels.append(parts[1])
            data.append(parts[2])


    return data, targets, labels



##########################
# bag of words functions
##########################



'''
Creates bag of words string representaion for a given CVE from programming code.

@param      path to CVE directory (with commit/note file)
@return     bag of words string
'''
def createBagOfWordsElementFromCode(cveDir):
    commitFile = os.path.join(cveDir, 'commit')
    bag = []
    c = 0

    with open(commitFile, 'r') as f:

        for line in f:

            if c == 0 and line[0:3] == "---":
                c = 1
            elif c == 1 and line[0:3] == "+++":
                c = 2
            elif c == 2 and line[0:2] == "@@":
                c = 3
            elif c == 3:

                if line[0:3] == "---":
                    c = 1
                elif line[0] == "+" or line[0] == "-":
                    sign = line[0]
                    line = line[1:]

                    for element in line.split():
                        bag.append(sign + element)

    return " ".join(bag)



'''
Creates bag of words string representaion for a given CVE from note.

@param      path to CVE directory (with commit/note file)
@return     bag of words string
'''
def createBagOfWordsElementFromNote(cveDir):
    noteFile = os.path.join(cveDir, 'note')

    with open(noteFile, 'r') as f:
        return " ".join(f.readlines())

    return ''



'''
Creates bag of words string representaion for a given CVE from programming code and note.

@param      path to CVE directory (with commit/note file)
@return     bag of words string
'''
def createBagOfWordsElementFromBoth(cveDir):
    return createBagOfWordsElementFromCode(cveDir) + ' ' + createBagOfWordsElementFromNote(cveDir)



##########################
# evaluation functions
##########################



'''
calculates evaluation precision and recall for bayes.

@param      predicted values
@param      training data targets values
@param      category labels
@param      determines whether an output should be printed or not
@return     [precision, recall]
'''
def evaluateBayes(predicted, targets, categories, output = True):
    result = metrics.classification_report(targets, predicted, target_names=categories)
    summaryRow = result.split("\n")[7]
    summaryComponents = re.findall(r"[-+]?\d*\.\d+|\d+", summaryRow)[:2]

    if output:
        printEvaluation(summaryComponents[0], summaryComponents[1])

    return summaryComponents



'''
calculates evaluation metric components for kmeans.

@param      kmeans instance
@param      predicted values
@param      training data targets values
@param      determines whether an output should be printed or not
@return     [[precision, recall], completeness score, homogeneity score, adjusted rand score, adjusted mutual info score]
'''
def evaluateKmeans(kmeans, predicted, targets, output = True):
    clusters = []
    groups = []
    clusterResults = []
    recall = 0
    precision = 0


    # init target groups, cluster groups
    for j in range(kmeans.n_clusters):
        groups.append([])
        clusters.append([])
        clusterResults.append([])

    i = 0

    # group targets by categories
    for target in targets:
        groups[target].append(i)
        i = i + 1


    i = 0

    # loop target groups (grouped by categories)
    for group in groups:
        clusterResults[i] = evaluateKmeansCluster(kmeans, predicted, group)

        if output:
            precision = clusterResults[i][0]
            recall = clusterResults[i][1]

            print 'Classification index ' + str(i), clusterResults[i]
            printEvaluation(precision, recall)
            line()

        i = i + 1


    return [
        clusterResults,
        round(metrics.completeness_score(targets, predicted), 2),
        round(metrics.homogeneity_score(targets, predicted), 2),
        round(metrics.adjusted_rand_score(targets, predicted), 2),
        round(metrics.adjusted_mutual_info_score(targets, predicted), 2)
    ]



'''
calculates precision and recall for kmeans.

@param      kmeans instance
@param      predicted values
@param      group of training data targets for a single category (e.g. all bufferoverflow targets)
@return     [precision, recall]
'''
def evaluateKmeansCluster(kmeans, predicted, group):
    tmpClusters = []
    truePositivesCount = -1
    tmpClustersCount = 0
    pivotCluster = False
    k = 0


    # init temp clusters
    for j in range(kmeans.n_clusters):
        tmpClusters.append([])

    # group targets by cluster index in temp clusters
    for index in group:
        cluster = predicted[index]

        tmpClusters[cluster].append(index)


    # loop temp cluster and detect main cluster for the current category by max number of elements
    for cluster in tmpClusters:
        count = len(cluster)

        if truePositivesCount < count:
            pivotCluster = k
            truePositivesCount = count

        tmpClustersCount = tmpClustersCount + count
        k = k + 1

    falseNegativesCount = tmpClustersCount - truePositivesCount
    truePositivesCountSum = 0


    # group clusters
    for cluster in predicted:
        if cluster == pivotCluster:
            truePositivesCountSum = truePositivesCountSum + 1


    # precision = TP / (TP + FP) <=> TP / cluster-count
    precision = round(truePositivesCount / float(truePositivesCountSum), 2)


    # recall = TP / (TP + FN)
    recall = round(truePositivesCount / float((truePositivesCount + falseNegativesCount)), 2)


    return [precision, recall]



##########################
# utility functions
##########################


'''
builds evaluation csv file.

@param      output file path
@param      rows to write
@return     void
'''
def buildEvaluationFile(path, rows):
    with open(path, 'wb') as csvfile:
        writer = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

        for value in rows:
            writer.writerow(value)



'''
prints evaluation values (helper).

@param      precision
@param      recall
@return     void
'''
def printEvaluation(precision, recall):
    print 'precision =', precision
    print 'recall =', recall



'''
prints a line.

@return     void
'''
def line():
    print '-----------------------------'
