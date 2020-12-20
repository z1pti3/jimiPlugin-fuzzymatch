from core.models import action
from core import auth, db, helpers

from plugins.virustotal.includes import virustotal

class _virustotalIPDetails(action._action):
    ip = str()
    apiToken = str()

    def run(self,data,persistentData,actionResult):
        ip = helpers.evalString(self.ip,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        result = virustotal._virustotal(apiToken).ipDetails(ip)
        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["virustotal"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from virustotal API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_virustotalIPDetails, self).setAttribute(attr,value,sessionData=sessionData)

class _virustotalDomainDetails(action._action):
    domain = str()
    apiToken = str()

    def run(self,data,persistentData,actionResult):
        domain = helpers.evalString(self.domain,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)
    
        result = virustotal._virustotal(apiToken).domainDetails(domain)
        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["virustotal"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from virustotal API"
        return actionResult  

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_virustotalDomainDetails, self).setAttribute(attr,value,sessionData=sessionData)

class _virustotalFileDetails(action._action):
    sha256 = str()
    apiToken = str()

    def run(self,data,persistentData,actionResult):
        sha256 = helpers.evalString(self.sha256,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)
    
        result = virustotal._virustotal(apiToken).fileDetails(sha256)
        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["virustotal"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from virustotal API"
        return actionResult  

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_virustotalFileDetails, self).setAttribute(attr,value,sessionData=sessionData)

class _virustotalFileBehaviour(action._action):
    sha256 = str()
    apiToken = str()

    def run(self,data,persistentData,actionResult):
        sha256 = helpers.evalString(self.sha256,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)
    
        result = virustotal._virustotal(apiToken).fileBehaviour(sha256)
        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["virustotal"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from virustotal API"
        return actionResult  

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_virustotalFileBehaviour, self).setAttribute(attr,value,sessionData=sessionData)

class _virustotalFileSubmission(action._action):
    filename = str()
    apiToken = str()

    def run(self,data,persistentData,actionResult):
        filename = helpers.evalString(self.filename,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)
    
        result = virustotal._virustotal(apiToken).fileSubmission(filename)
        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["virustotal"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from virustotal API"
        return actionResult  

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_virustotalFileBehaviour, self).setAttribute(attr,value,sessionData=sessionData)