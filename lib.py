from sklearn import metrics
import numpy as np;
import os, csv, re;


'''
training data function
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


'''
bag of words functions
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


def createBagOfWordsElementFromNote(cveDir):
    noteFile = os.path.join(cveDir, 'note')

    with open(noteFile, 'r') as f:
        return " ".join(f.readlines())

    return ''


def createBagOfWordsElementFromBoth(cveDir):
    return createBagOfWordsElementFromCode(cveDir) + ' ' + createBagOfWordsElementFromNote(cveDir)




'''
evaluate function
'''

def evaluateBayes(predicted, targets, categories, output = True):
    result = metrics.classification_report(targets, predicted, target_names=categories)
    summaryRow = result.split("\n")[7]
    summaryComponents = re.findall(r"[-+]?\d*\.\d+|\d+", summaryRow)[:2]

    if output:
        printEvaluation(summaryComponents[0], summaryComponents[1])

    return summaryComponents


def evaluateKmeans(kmeans, targets, output = True):
    predicted = kmeans.labels_
    clusters = []
    groups = []
    recall = 0
    precision = 0


    # init target groups, cluster groups
    for j in range(kmeans.n_clusters):
        groups.append([])
        clusters.append([])

    i = 0

    # group targets by categories
    for target in targets:
        groups[target].append(i)
        i = i + 1

    i = 0

    # group clusters
    for cluster in predicted:
        clusters[cluster].append(i)
        i = i + 1


    # loop target groups (grouped by categories)
    for group in groups:
        tmpClusters = []
        mainClusterCount = -1
        mainCluster = False
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

            if mainClusterCount < count:
                mainCluster = k
                mainClusterCount = count

            k = k + 1

        # calculate recall value
        recall = recall + mainClusterCount/float(len(group))
        precision = precision + mainClusterCount/float(len(clusters[mainCluster]))



    precision = round(precision/float(kmeans.n_clusters), 2)
    recall = round(recall/float(kmeans.n_clusters), 2)

    if output:
        printEvaluation(precision, recall)


    return [precision, recall]


def evaluateKmeansARI(kmeans, targets):
    print metrics.adjusted_rand_score(targets, kmeans.labels_)
    print targets
    print kmeans.labels_

def evaluateKmeansARI2(predicted, targets):
    print metrics.adjusted_rand_score(targets, predicted)
    print targets
    print predicted
    print metrics.adjusted_mutual_info_score(targets, predicted)
    print metrics.homogeneity_score(targets, predicted)
    print metrics.completeness_score(targets, predicted)


'''
utility functions
'''

def printEvaluation(precision, recall):
    print 'precision =', precision
    print 'recall =', recall


def line():
    print '-----------------------------'
