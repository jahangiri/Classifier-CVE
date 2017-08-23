import xml.etree.ElementTree as ET
import re, os, urllib
import json
import urllib2
import getpass


#config
cveFile = 'cvelist.xml'
cveUrl = "https://cve.mitre.org/data/downloads/allitems-cvrf.xml"

#xml namespace
ns = 'http://www.icasi.org/CVRF/schema/vuln/1.1'

#output directory to save the end data
outputDir = 'CVE-directories'

#code response to skip
skipResponseCodes = [404]

u = raw_input('Benutzername:')
p = getpass.getpass('Passwort:')


def encodeUserData(user, password):
    return "Basic " + (user + ":" + password).encode("base64").rstrip()


#create output directory
if not os.path.exists(outputDir):
    os.makedirs(outputDir)
    print 'output dir created', outputDir


#Datei runterladen, falls nicht existiert
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

for v in root.findall('{'+ns+'}Vulnerability'):

    #iterate CVE tag
    cveID = v.find('{'+ns+'}CVE').text


    for n in v.findall('{'+ns+'}Notes'):
        note = n.find('{'+ns+'}Note').text

        #TODO eventuell mehrere notes? array erstellen um die anzuhaengen


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

                    print('---------------------------------------------')

                    #get response code
                    code = urllib.urlopen(patchUrl).getcode() #TODO urllib2 ?


                    if code in skipResponseCodes:
                        print('[SKIP][code='+str(code)+']'+patchUrl)
                    else:

                        # path for local repository directory to save commits
                        cveDir = os.path.join(outputDir, cveID)

                        #create path for commitfile
                        commitFile = os.path.join(cveDir, 'commit')

                        #create path for notefile
                        noteFile = os.path.join(cveDir, 'note')

                        #create directory for repository (if not exist)
                        if not os.path.exists(cveDir):
                            os.makedirs(cveDir)

                        #load file and save
                        o = urllib.FancyURLopener() #TODO urllib2 ?
                        o.retrieve(patchUrl, commitFile)

                        with open(noteFile, "w") as textFile:
                            textFile.write(note)


                        print('[OK][code='+str(code)+']'+patchUrl)
            except Exception as e:
                print('[EXCEPTION]'+cveID)
                print(e)

print 'done'
