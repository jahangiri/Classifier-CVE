import xml.etree.ElementTree as ET
import re, os, urllib
import json
import urllib2
import getpass
from code_classifier_lib import *

print 'start'

file = 'cvelist.xml'
url = urllib.FancyURLopener()
url.retrieve("https://cve.mitre.org/data/downloads/allitems-cvrf.xml", file)


print 'CVE-Datei download abgeschlossen'


#xml namespace
ns = 'http://www.icasi.org/CVRF/schema/vuln/1.1'


#output directory to save the end data
outputDir = 'endresult_bag3'


#code response to skip
skipResponseCodes = [404]


tree = ET.parse(file)
root = tree.getroot();

bagAll = []
bagAllLabel = []


breakIndex = 0
l = 0
k = input('Anzahl an Cluster angeben:')

#create output directory
if not os.path.exists(outputDir):
    os.makedirs(outputDir)


u = raw_input('Benutzername:')
p = getpass.getpass('Passwort:')

#iterate all vulnerability tags
for v in root.findall('{'+ns+'}Vulnerability'):

    #iterate CVE tag
    cveID = v.find('{'+ns+'}CVE').text


    #iterate cve references and search for github Commit
    #commit format: "CONFIRM:https://github.com/{username}/{reponame}/commit/{commitID}"
    for ref in v.findall('{'+ns+'}References//{'+ns+'}Reference'):
        description = ref.find('{'+ns+'}Description').text
        regexResult = re.search('^CONFIRM:https://github.com/([^/]*)/([^/]*)/commit/(.*)', description)


        #commit found
        if regexResult:

            #"CONFIRM" extract
            url = re.sub('^CONFIRM:', '', description)

            #create pach url to get last commit change
            patchUrl = url + ".patch"

            #extract username from regex
            username = regexResult.group(1)

            #extract reponame from regex
            reponame = regexResult.group(2)

            #extract Commit-ID from regex
            commitID = regexResult.group(3)


            try:

                # URL for github api
                jsonurl = "https://api.github.com/repos/"+username+"/"+reponame

                url = jsonurl

                # create the request object and set some headers
                req = urllib2.Request(url)
                req.add_header('Accept', 'application/json')
                req.add_header("Content-type", "application/x-www-form-urlencoded")
                req.add_header('Authorization', encodeUserData(u, p))
                # make the request and print the results
                res = urllib2.urlopen(req)
                # @source https://stackoverflow.com/questions/2667509/curl-alternative-in-python

                data = json.loads(res.read())


                if  'language' in data and data['language'] == 'C':

                    # path for local repository directory to save commits
                    repoDir = os.path.join(outputDir, username+"~"+reponame)

                    #create path for commitfile
                    commitFile = os.path.join(repoDir, commitID)


                    #load patch from github in file
                    try:
                        print('---------------------------------------------')
                        l = l +1
                        print l

                        #get response code
                        code = urllib.urlopen(patchUrl).getcode()

                        if code in skipResponseCodes:
                            print('[SKIP][code='+str(code)+']'+patchUrl)
                        else:

                            #create directory for repository (if not exist)
                            if not os.path.exists(repoDir):
                                os.makedirs(repoDir)

                            #load file and save
                            o = urllib.FancyURLopener()
                            o.retrieve(patchUrl, commitFile)

                            print('[OK][code='+str(code)+']'+patchUrl)

                            #create bag of words from commit
                            bag = createBag(commitFile)

                            bagAll.append(bag)
                            bagAllLabel.append(cveID)


                    except Exception as e:
                        print(index,'[EXCEPTION]'+patchUrl)
                        print(e)


                    break

            except Exception as e:
                print('[EXCEPTION][code='+str(code)+']'+patchUrl)
                print(e)


print '-------------------'
print bagAll
print '-------------------------'
print 'gesamter bag wird erstellt'

createBagAll(bagAll, bagAllLabel, k)
