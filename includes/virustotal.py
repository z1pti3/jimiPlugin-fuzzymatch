import requests
import json
import time
from pathlib import Path

class _virustotal():
    url = "https://www.virustotal.com/api/v3"

    def __init__(self, apiToken, ca=None, requestTimeout=30):
        self.requestTimeout = requestTimeout
        self.apiToken = apiToken
        self.headers = {
            "x-apikey" : self.apiToken
        }
        if ca:
            self.ca = Path(ca)
        else:
            self.ca = None

    def apiCall(self,collection,objectID,extra=""):
        kwargs={}
        kwargs["timeout"] = self.requestTimeout
        kwargs["headers"] = self.headers
        if self.ca:
            kwargs["verify"] = self.ca
        try:
            url = "{0}/{1}/{2}{3}".format(self.url,collection,objectID,extra)
            response = requests.get(url, **kwargs)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            return 0, "Connection Timeout"
        if response.status_code == 200:
            return response.text
        return None

    def ipDetails(self,ip,summary=True):
        def getKey(dictObj,key):
            try:
                return dictObj[key]
            except KeyError:
                return None
        response = self.apiCall("ip_addresses",ip)
        if response:
            response = json.loads(response)
            if summary:
                result = { 
                    "last_modification_date" : getKey(response["data"]["attributes"],"last_modification_date"),
                    "asn" : getKey(response["data"]["attributes"],"asn"), 
                    "as_owner" : getKey(response["data"]["attributes"],"as_owner"),
                    "country" : getKey(response["data"]["attributes"],"country"),
                    "network" : getKey(response["data"]["attributes"],"network"),
                    "reputation" : getKey(response["data"]["attributes"],"reputation"),
                    "whois" : getKey(response["data"]["attributes"],"whois"),
                    "whois_date" : getKey(response["data"]["attributes"],"whois_date"),
                    "harmless" : getKey(response["data"]["attributes"]["last_analysis_stats"],"harmless"),
                    "malicious" : getKey(response["data"]["attributes"]["last_analysis_stats"],"malicious"),
                    "suspicious" : getKey(response["data"]["attributes"]["last_analysis_stats"],"suspicious"),
                    "timeout" : getKey(response["data"]["attributes"]["last_analysis_stats"],"timeout"),
                    "undetected" : getKey(response["data"]["attributes"]["last_analysis_stats"],"undetected"),
                    "votes_harmless" : getKey(response["data"]["attributes"]["total_votes"],"harmless"),
                    "votes_malicious" : getKey(response["data"]["attributes"]["total_votes"],"malicious"),
                    "last_https_certificate_date" : getKey(response["data"]["attributes"],"last_https_certificate_date"),
                    "certificate_serial_number" : getKey(response["data"]["attributes"]["last_https_certificate"],"serial_number"),
                    "certificate_thumbprint" : getKey(response["data"]["attributes"]["last_https_certificate"],"thumbprint"),
                    "certificate_thumbprint_sha256" : getKey(response["data"]["attributes"]["last_https_certificate"],"thumbprint_sha256"),
                    "certificate_not_after" : getKey(response["data"]["attributes"]["last_https_certificate"]["validity"],"not_after"),
                    "certificate_not_before" : getKey(response["data"]["attributes"]["last_https_certificate"]["validity"],"not_before"),
                    "certificate_subject" : getKey(response["data"]["attributes"]["last_https_certificate"]["subject"],"CN"),
                    }
                return result
            else:
                return response
        return None

    def domainDetails(self,domain,summary=True):
        def getKey(dictObj,key):
            try:
                return dictObj[key]
            except KeyError:
                return None
        response = self.apiCall("domains",domain)
        if response:
            response = json.loads(response)
            if summary:
                result = { 
                    "last_modification_date" : getKey(response["data"]["attributes"],"last_modification_date"),
                    "reputation" : getKey(response["data"]["attributes"],"reputation"),
                    "whois" : getKey(response["data"]["attributes"],"whois"),
                    "whois_date" : getKey(response["data"]["attributes"],"whois_date"),
                    "harmless" : getKey(response["data"]["attributes"]["last_analysis_stats"],"harmless"),
                    "malicious" : getKey(response["data"]["attributes"]["last_analysis_stats"],"malicious"),
                    "suspicious" : getKey(response["data"]["attributes"]["last_analysis_stats"],"suspicious"),
                    "timeout" : getKey(response["data"]["attributes"]["last_analysis_stats"],"timeout"),
                    "undetected" : getKey(response["data"]["attributes"]["last_analysis_stats"],"undetected"),
                    "votes_harmless" : getKey(response["data"]["attributes"]["total_votes"],"harmless"),
                    "votes_malicious" : getKey(response["data"]["attributes"]["total_votes"],"malicious"),
                    "last_dns_records_date" : getKey(response["data"]["attributes"],"last_dns_records_date"),
                    "last_https_certificate_date" : getKey(response["data"]["attributes"],"last_https_certificate_date"),
                    "certificate_serial_number" : getKey(response["data"]["attributes"]["last_https_certificate"],"serial_number"),
                    "certificate_thumbprint" : getKey(response["data"]["attributes"]["last_https_certificate"],"thumbprint"),
                    "certificate_thumbprint_sha256" : getKey(response["data"]["attributes"]["last_https_certificate"],"thumbprint_sha256"),
                    "certificate_not_after" : getKey(response["data"]["attributes"]["last_https_certificate"]["validity"],"not_after"),
                    "certificate_not_before" : getKey(response["data"]["attributes"]["last_https_certificate"]["validity"],"not_before"),
                    "certificate_subject" : getKey(response["data"]["attributes"]["last_https_certificate"]["subject"],"CN"),
                    }
                return result
            else:
                return response
        return None

    def fileDetails(self,sha256,summary=True):
        def getKey(dictObj,key):
            try:
                return dictObj[key]
            except KeyError:
                return None
        response = self.apiCall("files",sha256)
        if response:
            response = json.loads(response)
            if summary:
                result = { 
                    "sha256" : sha256,
                    "last_modification_date" : getKey(response["data"]["attributes"],"last_modification_date"),
                    "last_submission_date" : getKey(response["data"]["attributes"],"last_submission_date"),
                    "last_analysis_date" : getKey(response["data"]["attributes"],"last_analysis_date"),
                    "reputation" : getKey(response["data"]["attributes"],"reputation"),
                    "whois" : getKey(response["data"]["attributes"],"whois"),
                    "whois_date" : getKey(response["data"]["attributes"],"whois_date"),
                    "harmless" : getKey(response["data"]["attributes"]["last_analysis_stats"],"harmless"),
                    "malicious" : getKey(response["data"]["attributes"]["last_analysis_stats"],"malicious"),
                    "suspicious" : getKey(response["data"]["attributes"]["last_analysis_stats"],"suspicious"),
                    "timeout" : getKey(response["data"]["attributes"]["last_analysis_stats"],"timeout"),
                    "undetected" : getKey(response["data"]["attributes"]["last_analysis_stats"],"undetected"),
                    "unsupported" : getKey(response["data"]["attributes"]["last_analysis_stats"],"type-unsupported"),
                    "failure" : getKey(response["data"]["attributes"]["last_analysis_stats"],"failure"),
                    "confirmed_timeout" : getKey(response["data"]["attributes"]["last_analysis_stats"],"confirmed-timeout"),
                    "meaningful_name" : getKey(response["data"]["attributes"],"meaningful_name"),
                    "size" : getKey(response["data"]["attributes"],"size"),
                    "type_extension" : getKey(response["data"]["attributes"],"type_extension"),
                    "unique_sources" : getKey(response["data"]["attributes"],"unique_sources"),
                    "type_tag" : getKey(response["data"]["attributes"],"type_tag"),
                    "type_description" : getKey(response["data"]["attributes"],"type_description"),
                    "times_submitted" : getKey(response["data"]["attributes"],"times_submitted"),
                    "downloadable" : getKey(response["data"]["attributes"],"downloadable"),
                    "votes_harmless" : getKey(response["data"]["attributes"]["total_votes"],"harmless"),
                    "votes_malicious" : getKey(response["data"]["attributes"]["total_votes"],"malicious"),
                    }
                return result
            else:
                return response
        return None

    def fileBehaviour(self,sha256):
        response = self.apiCall("files",sha256,"/behaviour_summary")
        if response:
            response = json.loads(response)
            return response
        return None

    def fileSubmission(self,localFilename,waitAnalyses=True):
        kwargs={}
        kwargs["timeout"] = self.requestTimeout
        kwargs["headers"] = self.headers
        if self.ca:
            kwargs["verify"] = self.ca
        try:
            url = "{0}/{1}".format(self.url,"files")
            filename = localFilename.split("/")[-1]
            with open(str(Path(localFilename)), 'rb') as f:
                response = requests.post(url, files={"file": f.read()}, **kwargs)
            if response.status_code == 200:
                id = json.loads(response.text)["data"]["id"]
                if waitAnalyses:
                    time.sleep(1)
                    for x in range(0,60):
                        response = self.apiCall("analyses",id)
                        if response:
                            response = json.loads(response)
                            if response["data"]["attributes"]["status"] == "completed":
                                return self.fileDetails(response["meta"]["file_info"]["sha256"])
                        time.sleep(10)
                return id
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            return 0, "Connection Timeout"
        if response.status_code == 200:
            return response.text
        return None
