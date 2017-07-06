import re, json
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.feature_extraction.text import TfidfVectorizer
import matplotlib.pyplot as plt
from sklearn.externals import joblib
import pandas as pd
from sklearn.cluster import KMeans



#simple wrapper function to encode the username & pass
def encodeUserData(user, password):
    return "Basic " + (user + ":" + password).encode("base64").rstrip()


#function to create bag of words
def createBag(commitFile):

    print'create bag'


    #path for bag of words file
    bagFile = commitFile + ".bag"

    #init empty bag array
    bag = []

    c = 0

    #load file content
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


def createBagAll(bagAll, bagAllLabel, k):
    k = input('Anzahl an Cluster angeben:')
    i = 0
    clusters = [None]*k

    #create bag of words vector
    vectorizer = TfidfVectorizer(token_pattern = u'([^\s]+)\s*')
    x = vectorizer.fit_transform(bagAll)
    y = x.toarray()
    vocab = vectorizer.get_feature_names()

    #perform kmeans algorithm
    model = KMeans(n_clusters = k, init = 'k-means++', max_iter = 100)
    model.fit(x)

    print model.labels_
    print bagAllLabel

    #index for searching CVEs
    for c in model.labels_:

        if clusters[c] is None:
            clusters[c] = []

        clusters[c].append(bagAllLabel[i])
        i = i + 1


    for j in range(k):

        print 'Cluster ' + str(j+1)
        print clusters[j]
        print '-----------------------'

    #userinput for CVE search
    while True:

        userinput = raw_input('CVE-Eingeben:')

        if userinput not in bagAllLabel:

            print 'Eintrag nicht vorhanden'

        else:

            found = bagAllLabel.index(userinput)

            print model.labels_[found]
