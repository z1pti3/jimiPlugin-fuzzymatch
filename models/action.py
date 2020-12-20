from fuzzywuzzy import fuzz
import jellyfish
from core.models import action
from core import auth, db, helpers

class _fuzzymatchString(action._action):
    checkString = str()
    matchString = str()

    def run(self,data,persistentData,actionResult):
        checkString = helpers.evalString(self.checkString,{"data" : data})
        matchString = helpers.evalString(self.matchString,{"data" : data})
        result = jellyfish.match_rating_comparison(checkString,matchString)
        if result == None:
            actionResult["result"] = False
            actionResult["msg"] = "Strings are far apart"
            actionResult["rc"] = 21
            return actionResult 

        actionResult["result"] = result
        actionResult["rc"] = 0
        return actionResult 

class _fuzzymatchList(action._action):
    checkString = str()
    matchList = list()

    def run(self,data,persistentData,actionResult):
        checkString = helpers.evalString(self.checkString,{"data" : data})
        matchList = helpers.evalList(self.matchList,{"data" : data})
        results = {}
        for matchString in matchList:
            result = jellyfish.match_rating_comparison(checkString,matchString)
            if result:
                results[matchString] = result
        if results:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["results"] = results
        else:
            actionResult["result"] = False
            actionResult["rc"] = 1
        return actionResult 

class _fuzzymatchLevenshteinDistance(action._action):
    checkString = str()
    matchString = str()
    matchAboveScore = int()

    def run(self,data,persistentData,actionResult):
        checkString = helpers.evalString(self.checkString,{"data" : data})
        matchString = helpers.evalString(self.matchString,{"data" : data})
        score = fuzz.ratio(checkString,matchString)
        if score > self.matchAboveScore:
            actionResult["result"] = True
            actionResult["rc"] = 0
        else:
            actionResult["result"] = False
            actionResult["rc"] = 1
        actionResult["score"] = score
        return actionResult 

