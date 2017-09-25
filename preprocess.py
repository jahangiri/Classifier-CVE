import xml.etree.ElementTree as ET
import re, os, urllib, urllib2, json, getpass


'''
@description The CVE commits and notes are downloaded and saved into separated directories
@author Reza Jahangiri <s6rejaha@uni-bonn.de>
'''


'''
configuration
'''

# cve download url
cveUrl = "https://cve.mitre.org/data/downloads/allitems-cvrf.xml"

# cve output file
cveFile = 'cvelist.xml'

# xml namespace
ns = 'http://www.icasi.org/CVRF/schema/vuln/1.1'

# output directory to save the end data
outputDir = 'CVE-directories'

# code response to skip
skipResponseCodes = [404]


'''
start code execution
'''


# read login data for github from console
u = raw_input('Benutzername:')
p = getpass.getpass('Passwort:')

# build github authorization header for request
authorizationHeader = "Basic " + (u + ":" + p).encode("base64").rstrip()


# create output directory
if not os.path.exists(outputDir):
    os.makedirs(outputDir)
    print 'output dir created', outputDir


# download file, if not already exists
if not os.path.exists(cveFile):
    url = urllib.FancyURLopener()
    url.retrieve(cveUrl, cveFile)
    print 'CVE-Datei download abgeschlossen'
else:
    print 'CVE file exists'


print 'parse CVE file'

tree = ET.parse(cveFile)
root = tree.getroot();


print 'start looping file'

# loop CVE xml data
for v in root.findall('{'+ns+'}Vulnerability'):

    # iterate CVE tag
    cveID = v.find('{'+ns+'}CVE').text


    # get note from CVE xml data
    for n in v.findall('{'+ns+'}Notes'):
        note = n.find('{'+ns+'}Note').text


    # iterate cve references and search for github Commit
    # commit format: "CONFIRM:https://github.com/{username}/{reponame}/commit/{commitID}"
    for ref in v.findall('{'+ns+'}References//{'+ns+'}Reference'):
        description = ref.find('{'+ns+'}Description').text
        regexResult = re.search('^CONFIRM:https://github.com/([^/]*)/([^/]*)/commit/(.*)', description)


        # commit found
        if regexResult:

            # "CONFIRM" extract
            url = re.sub('^CONFIRM:', '', description)

            # create pach url to get last commit change
            patchUrl = url + ".patch"

            # extract username from regex
            username = regexResult.group(1)

            # extract reponame from regex
            reponame = regexResult.group(2)

            # extract Commit-ID from regex
            commitID = regexResult.group(3)


            try:

                # URL for github api
                jsonurl = "https://api.github.com/repos/"+username+"/"+reponame

                url = jsonurl

                # create and send the request object with some headers
                # @source https://stackoverflow.com/questions/2667509/curl-alternative-in-python
                req = urllib2.Request(url)
                req.add_header('Accept', 'application/json')
                req.add_header("Content-type", "application/x-www-form-urlencoded")
                req.add_header('Authorization', authorizationHeader)
                res = urllib2.urlopen(req)

                # get json from response
                data = json.loads(res.read())

                # consider only programming language C
                if  'language' in data and data['language'] == 'C':

                    print('---------------------------------------------')

                    # get response code
                    code = urllib.urlopen(patchUrl).getcode() #TODO urllib2 ?

                    # skip error response codes e.g. 404
                    if code in skipResponseCodes:
                        print('[SKIP][code='+str(code)+']'+patchUrl)
                    else:

                        # path for local repository directory to save commits
                        cveDir = os.path.join(outputDir, cveID)

                        # create path for commit file
                        commitFile = os.path.join(cveDir, 'commit')

                        # create path for note file
                        noteFile = os.path.join(cveDir, 'note')

                        # create directory for repository (if not exists)
                        if not os.path.exists(cveDir):
                            os.makedirs(cveDir)

                        # load commit and save in file
                        o = urllib.FancyURLopener() #TODO urllib2 ?
                        o.retrieve(patchUrl, commitFile)

                        # save note in file
                        with open(noteFile, "w") as textFile:
                            textFile.write(note)

                        print('[OK][code='+str(code)+']'+patchUrl)

            except Exception as e:
                print('[EXCEPTION]'+cveID)
                print(e)

print 'done'
