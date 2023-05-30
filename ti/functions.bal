// Copyright (c) 2023, WSO2 Inc. (http://www.wso2.com). All Rights Reserved.
// 
// This software is the property of WSO2 Inc. and its suppliers, if any.
// Dissemination of any information or reproduction of any material contained
// herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
// You may not alter or remove any copyright or other notice from copies of this content.

import ballerina/http;
import ballerina/lang.runtime;
import ballerina/log;
import ballerina/regex;
import ballerina/time;
import ballerina/xmldata;
import ballerinax/googleapis.sheets;

# Calling the machine learing model endpoint for filtering the threat intel feeds.
# If the feed is 'relevant' returns 'FILTERED', if not returns 'NOTFILTERED'. If any error occurs in the  ml endpoint returns 'ERROR'.
#
# + text - The feed which need to be filtered
# + return - Returns 'ReturnValues'(enum) or an error
public function mlFilteringModel(string text) returns string|error {
    final readonly & string[] replaceChar = ["\\n", "[^a-zA-Z0-9\\s]"];
    string cleanText = text;
    foreach string item in replaceChar {
        cleanText = regex:replaceAll(cleanText, item, "");
    }
      
    http:Client httpClientML = check new (mlModelBaseUrl);
    http:Request reqML = new;
    //payload(the input) should be in this format
    json payload = {
                "Inputs": {
                    "input1": [
                    {
                        "Category": "not_relevent",
                        "Text": cleanText
                    }
                    ]
                },
                "GlobalParameters": {}
                };
    reqML.setJsonPayload(payload);
    reqML.addHeader("Authorization", "Bearer " + mlModelBearerToken);
   
    http:Response response = check httpClientML->post(path = "", message = (reqML));
    if response.statusCode != http:STATUS_OK {
        log:printError("ML endpoint error. Status code:- " + response.statusCode.toString());
        return ERROR;
    } else {
        json getResponse = check response.getJsonPayload();
        json getResult = check getResponse.Results;
        json[] webServiceOutput = check getResult.WebServiceOutput0.ensureType();
        map<json> label = check webServiceOutput[0].ensureType();
        return label["Scored Labels"] == "relevant" ? FILTERED : NOTFILTERED;
    }
}

# Reduce the content of a string by given word amount.
#
# + content - The string which is needed to reduce the content
# + amount - The amount
# + return - Content reduced string
public function reduceContent(string content, int amount) returns string {
    string[] splitDes = regex:split(content, " ");
    int countWords = 0;
    string reduceContentOfDes = "";
    foreach string word in splitDes {
        if countWords < amount {
            reduceContentOfDes = string:'join(" ", reduceContentOfDes, word);
        }
        countWords += 1;
    }
    return reduceContentOfDes;
}

# Check the similarity of two strings.
#
# + s1 - First string
# + s2 - Second string
# + return - Similarity score of the two strings
public function similarity(string s1, string s2) returns float {
    int len1 = s1.length();
    int len2 = s2.length();

    // initialize a 2D array with dimensions (len1+1) x (len2+1)
    int[][] matrix = [];
   
    // fill in the first row and column of the matrix
    foreach int i in 0...len1 {
        matrix[i][0] = i;
    }
    foreach int j in 0...len2 {
        matrix[0][j] = j;
    }
  
    // fill in the rest of the matrix
    foreach int i in 1...len1 {
        foreach int j in 1...len2 {
            if (s1[i - 1] == s2[j - 1]) {
                matrix[i][j] = matrix[i - 1][j - 1];
            } else {
                matrix[i][j] = 1 + int:min(matrix[i - 1][j], matrix[i][j - 1], matrix[i - 1][j - 1]);
            }
        }
    }

    // the Levenshtein Distance is the value in the bottom-right cell of the matrix.
    // the similarity score is the inverse of the Levenshtein Distance, normalized by the length of the longer 
    // string.
    // similarityScore = 1 - matrix[len1][len2] / maxvalueof(len1,len2);

    return 1 - <float>matrix[len1][len2] / int:max(len1,len2);
}

# Function which filtering feeds according to keywords, machine learning model and CVE numbers.
#
# + feedDetails - A record which includes all feed details of a specific threat intel  
# + sheetsEp - Sheet client endpoint
# + feedShouldFiltered - The feed should be filtered or not
# + mlFilteringMode - The feed should be filtered using the machine learning model or not
# + return - Returns 'ReturnValues'(enum) or an error
public function filterFeeds(json feedDetails, sheets:Client sheetsEp, string feedShouldFiltered, 
    string mlFilteringMode) returns string|error {
    string filteringString = ((check feedDetails.link).toString() + " " + (check feedDetails.title).toString()
        + " " + (check feedDetails.description).toString()).toLowerAscii();
    // filteringString includes feed's title + description in lowercase.

    boolean mainFiltering = false;
    string|error mlFiltered = NOTFILTERED;
    boolean cveFiltered = false;

    // filtering the feed according to keywords. if filteringString includes
    // one of the key words in keyWords array then mainFiltering become true. 
    if feedShouldFiltered == "yes" {
        
        foreach string word in keyWordsLowerCase {
            if filteringString.includes(word) {
                if mlFilteringMode == "on" {
                    string text = string:'join(" ", (check feedDetails.title).toString(), (check feedDetails.description).toString());
                    mlFiltered = mlFilteringModel(text);
                    runtime:sleep(0.50);
                    if mlFiltered is error {
                        log:printError("An error occurred in the `mlFilteringModel()` function.", mlFiltered);
                        return ERROR;
                    }else if mlFiltered == ERROR {
                        log:printError("An error occurred in the machine learning endpoint.");
                        return ERROR;
                    }else if mlFiltered == FILTERED {
                        mainFiltering = true;
                    }  
                } else if mlFilteringMode == "off" {
                    mainFiltering = true;
                } else {
                    log:printError("ML Filtering mode value is not either 'on' or 'off'. Check the Spreadsheet.");
                    return ERROR;
                }
                break;
            }
        }

    } else if feedShouldFiltered == "no" {
        mainFiltering = true;
    }

    // filtering the feed according to  CVE numbers. if filteringString includes new CVE numbers cveFiltered becomes true. 
    if filteringString.includes("cve-") {

        string[] cveNumArray = [];
        // the array which will  include all the CVE numbers which are included in the relevant feed.
        regex:Match[] cveNumbers = regex:searchAll(filteringString, "cve-[0-9]{4}-[0-9]+");

        // extracting all CVE numbers in the filteringString into cveNumbers array.
        foreach int x in 0 ... cveNumbers.length() - 1 {
            if cveNumArray.indexOf(cveNumbers[x]["matched"]) !is int {
                cveNumArray.push(cveNumbers[x]["matched"]);
            }
        }

        (string|int|decimal)[] cveNums = [];
        // the variable which will be assigned the all CVE numbers which are in the spreadsheet.

        string[] addCevNumbers = [];
        // will add CVE numbers from cveNumArray to addCevNumbers array if those will not include in cveNums;

        // getting column A values from the spreadsheet. 
        // name of the spreadsheet 'TI_Solution-V2'. name of the subsheet 'CVE_ids' 
        sheets:Column|error column = sheetsEp->getColumn(spreadSheetId, sheetNameCveIds, "A");
        runtime:sleep(1);
        if column is sheets:Column {
            // assigning column A values in the spreadsheet to cveNums.
            // name of the spreadsheet 'TI_Solution-V2'. name of the subsheet 'CVE_ids' 
            cveNums = column.values;

            // checking if there are any CVE numbers in cveNumArray which already contains in cveNums.
            foreach string item in cveNumArray {
                if cveNums.indexOf(item) !is int {
                    // if the current item (CVE number) is not in the cveNums, push it to addCevNumbers.
                    addCevNumbers.push(item);
                } 
            }

            if addCevNumbers.length() != 0 {
                // new CVE numbers are found.
                cveFiltered = true;

                foreach string cveNum in addCevNumbers {
                    string[] cveNumberAndDate = [cveNum, check getDate(0)];
                    sheets:A1Range setSheetName = {sheetName:sheetNameCveIds};
                    error|sheets:ValueRange appendCveNumbers = sheetsEp->appendValue(spreadSheetId,cveNumberAndDate,setSheetName);
                    runtime:sleep(0.75);
                    if appendCveNumbers is error {
                        log:printError("An error occurred  when sending CVE numbers to the Spreadshaeet.");
                        return ERROR;
                    }
                }
            }

        } else {
            log:printError("An error occurred when getting CVE numbers from the Spreadshaeet.");
            return ERROR;
        }
    }

    if mainFiltering == true && filteringString.includes("cve-") == false {
        // if feed has a key word which in keyWords array and not includes any CVE number then return FILTERED
        return FILTERED;
    } else if mainFiltering == true && filteringString.includes("cve-") == true {
        if cveFiltered == true {
            // if feed has a key word which in keyWords array and feed has new CVE numbers then return FILTERED
            return FILTERED;
        }
    }
    return NOTFILTERED;
}

# Process of adding new feeds. Created this function to improve the code readability.
#
# + nameOfFeed - Name of the feed eg:- 'hackernews', 'bleeping computer'   
# + feedDetails - A record which includes all feed details of a specific threat intel  
# + sheetsEp - Sheet client endpoint
# + feedLastRecCellRange - Cell range of latest feed record (includes url and title + description)  
# + feedLastRecUrl - TI source's latest feed url which is recorded in the Spreadsheet
# + feedLastRecTitelAndDes - Lastest feed record's 'title + description'
# + feedShouldFiltered - Feed should be filtered or not
# + mlFilteringMode - Feed should be filtered using mlModel or not
# + return - Null or an error
public function addNewFeeds(string nameOfFeed, ItemDetails[] feedDetails, sheets:Client sheetsEp,
    string feedLastRecCellRange, string feedLastRecUrl, string feedLastRecTitelAndDes, string feedShouldFiltered, 
    string mlFilteringMode) returns error? {

    // new feeds will be added to the records.
    string[][] records = [];
    boolean isErrorInFiltering = false;
    
    foreach int i in 0 ..< feedDetails.length() {
        
        // if the threat intel is new to the system 
        if feedLastRecUrl == "new_feed" {
            string[][] entries = [[feedDetails[0].link.toString(), feedDetails[0].title.toString() + " " + 
                reduceContent(feedDetails[0].description.toString(), 30)]];
            sheets:Range setRange = {a1Notation: feedLastRecCellRange, values: entries};
            error? setLastRecord = sheetsEp->setRange(spreadSheetId, sheetNameMetaData, setRange);
            runtime:sleep(0.75);
            if setLastRecord is error {
                log:printError(check setAlertMessage(nameOfFeed + " :- Failed to add the TI feed. " + setLastRecord.toString()));
                return;
            }
            log:printInfo(check setAlertMessage(nameOfFeed + " TI feed is added."));
            return;
        }

        log:printInfo("*** Feed No: " + (i + 1).toString() + " ***");

        // i th index feed's title and description which is in feedDetails array.
        string indexIFeedTitleAndDes = feedDetails[i].title.toString() + " " + reduceContent(feedDetails[i].description.toString(), 30);

        // checking latest feed url in feedDetails is equal with feedLastRecUrl or similarity between indexIFeedTitleAndDes and 
        // feedLastRecTitelAndDes.
       
        if feedDetails[i].link.toString() == feedLastRecUrl || similarity(indexIFeedTitleAndDes, feedLastRecTitelAndDes) > 0.8 {
            
            if i == 0 {
                // this means Last record  of relevant feed is still the latest feed.
                log:printInfo("This is the latest feed.");
                return;
            } else {
                log:printInfo("This feed is already recorded.");
                if isErrorInFiltering == false {
                    string[][] reverserecords = records.reverse();

                    foreach int x in 0 ... records.length() - 1 {
                        string[] vals = [
                            reverserecords[x][0],
                            reverserecords[x][1],
                            reverserecords[x][2],
                            reverserecords[x][3],
                            reverserecords[x][4]
                        ];
                        sheets:A1Range setSheetName = {sheetName:sheetNameAlerts};
                        error|sheets:ValueRange appendRow = sheetsEp->appendValue(spreadSheetId, vals,setSheetName);
                        runtime:sleep(0.75);
                        if appendRow is error {
                            log:printError(check setAlertMessage(nameOfFeed + " :- An error occurred  when sending data to the Spreadsheet."));

                            // updating the latest record as the last record. index 0 includes the newest record!
                            string[][] entries = [[feedDetails[0].link.toString(), feedDetails[0].title.toString() + " " + 
                                reduceContent(feedDetails[0].description.toString(), 30)]];
                            sheets:Range setRange = {a1Notation: feedLastRecCellRange, values: entries};

                            error? setLastRecord = sheetsEp->setRange(spreadSheetId, sheetNameMetaData, setRange);
                            runtime:sleep(0.75);

                            if setLastRecord is error {
                                log:printError(check setAlertMessage(nameOfFeed + ":- Failed to update the latest record. " 
                                + setLastRecord.toString()));
                                return;
                            }
                            log:printInfo("Last record is updated.");
                            return;
                        }
                    }

                    log:printInfo(records.length().toString() + " records are send to the Spreadsheet (1st).");

                } else {
                    log:printError(check setAlertMessage(nameOfFeed + " :- An error occurred  in the filtering process." +
                        " Please check Choreo logs for further information."));

                }

                // updating the latest record as the last record. index 0 includes the newest record!
                string[][] entries = [[feedDetails[0].link.toString(), feedDetails[0].title.toString() + " " + 
                    reduceContent(feedDetails[0].description.toString(), 30)]];
                sheets:Range setRange = {a1Notation: feedLastRecCellRange, values: entries};

                error? setLastRecord = sheetsEp->setRange(spreadSheetId, sheetNameMetaData, setRange);
                runtime:sleep(0.75);

                if setLastRecord is error {
                    log:printError(check setAlertMessage(nameOfFeed + ":- Failed to update the latest record. " + setLastRecord.toString()));
                    return;
                }
                log:printInfo("Last record is updated.");
                return;
            }

        } else {
          
            // assign the i th index of feedDetail's data into passData json variable.
            json passData = {
                pubDate: feedDetails[i].pubDate,
                title: feedDetails[i].title,
                link: feedDetails[i].link,
                description: feedDetails[i].description
            };
            // get the return value of filteringFeeds function by passing passData json variable.
            // (which includes i th index of feedDetail's data)

            string|error isFiltered = filterFeeds(passData, sheetsEp, feedShouldFiltered, mlFilteringMode);

            if isFiltered == FILTERED {
                log:printInfo("<> feed is filtered.");
                // if isFiltered == FILTERED ,which means feed(i th index of feedDetail's data) is filtered. 
                // so it can add to the records array.
                string[] values = [
                    nameOfFeed,
                    (feedDetails[i].pubDate).toString(),
                    (feedDetails[i].title).toString(),
                    (feedDetails[i].link).toString(),
                    (feedDetails[i].description).toString()
                ];

                // push the filtered feed into records array.
                records.push(values);
            } else if isFiltered == ERROR {
                log:printError("Filtering error.");
                isErrorInFiltering = true;
                
            } else if isFiltered is error {
                log:printError("An error occurs in the `filteringFeeds()` function. ", isFiltered);
                isErrorInFiltering = true;
            } else {
                log:printInfo("<> feed is not filtered.");
            }
        }

    }

    // this happens when after traversing the whole array and couldn't find the url which recorded as the
    // last record of the relevant feed in the "last_record_of_feeds" sheet.
    if isErrorInFiltering == false {
        string[][] reverserecords = records.reverse();

        foreach int x in 0 ... records.length() - 1 {
            string[] vals = [
                reverserecords[x][0],
                reverserecords[x][1],
                reverserecords[x][2],
                reverserecords[x][3],
                reverserecords[x][4]
            ];
            sheets:A1Range setSheetName = {sheetName:sheetName};
            error|sheets:ValueRange appendRow = sheetsEp->appendValue(spreadSheetId, vals, setSheetName);
            runtime:sleep(0.75);
            if appendRow is error {
                log:printError(check setAlertMessage(nameOfFeed.toString() + " :- An error occurred  when sending data to the Spreadsheet. " 
                    + appendRow.toString()));

                // updating the latest record as the last record. index 0 includes the newest record!
                string[][] entries = [[feedDetails[0].link.toString(), feedDetails[0].title.toString() + " " +
                    reduceContent(feedDetails[0].description.toString(), 30)]];
                sheets:Range setRange = {a1Notation: feedLastRecCellRange, values: entries};

                error? setLastRecord = sheetsEp->setRange(spreadSheetId, sheetNameMetaData, setRange);
                runtime:sleep(0.75);

                if setLastRecord is error {
                    log:printError(check setAlertMessage(nameOfFeed + ":- Failed to update the latest record. " + 
                        setLastRecord.toString()));
                    return;
                }

                log:printInfo("Last record is updated.");
                return;
            }
        }

        log:printInfo(nameOfFeed.toString() + ":- " + records.length().toString() + " records are send to the Spreadsheet (2nd).");

    } else {
        log:printError(check setAlertMessage(nameOfFeed.toString() + ":- An error occurred in the filtering. Check Choreo logs."));
    }

    // updating the latest record as the last record. index 0 includes the newest record!
    string[][] entries = [[feedDetails[0].link.toString(), feedDetails[0].title.toString() + " " + 
        reduceContent(feedDetails[0].description.toString(), 30)]];
    sheets:Range setRange = {a1Notation: feedLastRecCellRange, values: entries};

    error? setLastRecord = sheetsEp->setRange(spreadSheetId, sheetNameMetaData, setRange);
    runtime:sleep(0.75);

    if setLastRecord is error {
        log:printError(check setAlertMessage(nameOfFeed + ":- Failed to update the latest record. " + setLastRecord.toString()));
        return;
    }
    log:printInfo("Last record is updated.");
    
}

# Returns the current date which is customized.
#
# + seconds - Time ajustment
# + return - Current date `mm/dd/yyyy` as a string
isolated function getDate(decimal seconds) returns string|error {
    // 19800 sec = 05 hours 30 mins
    time:Utc utc = time:utcAddSeconds(time:utcNow(), 19800 + seconds);
    time:Civil civil = time:utcToCivil(utc);
    json getTime = civil.toJson();
    map<json> mapDate = check getTime.ensureType();
    string date = mapDate["month"].toString() + "/" + mapDate["day"].toString() + "/" + mapDate["year"].toString();
    return date;
}

# Returns the current time which is customized.
#
# + seconds - Time ajustment 
# + return - Current time `hh:MM:ss` as a string
isolated function getTime(decimal seconds) returns string|error {
    // 19800 sec = 05 hours 30 mins
    time:Utc utc = time:utcAddSeconds(time:utcNow(), 19800 + seconds);
    time:Civil civil = time:utcToCivil(utc);
    json getTime = civil.toJson();
    map<json> mapTime = check getTime.ensureType();
    string hour = "";
    string min = "";
    string second = "";

    if mapTime["second"].toString()[1] == "." {
        second = "0" + mapTime["second"].toString()[0];
    } else {
        second = mapTime["second"].toString()[0] + mapTime["second"].toString()[1];
    }

    if mapTime["hour"].toString().length() == 1 {
        hour = "0" + mapTime["hour"].toString();
    } else {
        hour = mapTime["hour"].toString();
    }

    if mapTime["minute"].toString().length() == 1 {
        min = "0" + mapTime["minute"].toString();
    } else {
        min = mapTime["minute"].toString();
    }

    if mapTime["hour"].toString().length() == 1 {
        hour = "0" + mapTime["hour"].toString();
    } else {
        hour = mapTime["hour"].toString();
    }

    string time = hour + ":" + min + ":" + second;

    return time;
}

# Cleaning the given text. Mainly removing html tags.
#
# + text - Content which needs to clean
# + return - Return the content which is cleaned
public function clearText(json text) returns string|error {
    string theText = "";
    final readonly & string[][] replaceChar = [
        ["\\[", ""],["\\]", ""],["\",\"", ""],["\"", ""],["&lt;", "<"],["&gt;", ">"],["<.*?>", ""],["&amp;", "&"],
        ["#38;", ""],["nbsp;", "'"],["&.*?;", ""]
    ];

    if text.toString().includes("\"#content\"") {
        json getContent = (<map<json>>text).get("#content");
        theText = getContent.toString();

        foreach string[] regexPattern in replaceChar {
            theText = regex:replaceAll(theText, regexPattern[0], regexPattern[1]);

        }
    } else if text.toString().includes("@href") {

        json[] getItems = [];
        json getContent = {};
        do {
            getItems = check text.ensureType();
            getContent = (<map<json>>getItems[0]).get("@href");
            theText = getContent.toString();
        } on fail {
            getContent = (<map<json>>text).get("@href");
            theText = getContent.toString();
        }
    } else {
        theText = text.toString();
        foreach string[] regexPattern in replaceChar {
            theText = regex:replaceAll(theText, regexPattern[0], regexPattern[1]);
        }

    }
    return theText;
}

# Sends alert messages to the Spreadsheet. Also, the alert message will be recorded in the Choreo logs.
#
# + alert - The alert message
# + return - The alert message
public function setAlertMessage(string alert) returns string|error {
    string dateAlert = check getDate(0);
    string timeAlert = check getTime(0);
    string setAlertTime = string:'join(" at ",dateAlert,timeAlert);
    string[] alertMessage = [setAlertTime, alert];
    sheets:A1Range setSheetName = {sheetName:sheetNameAlerts};
    error|sheets:ValueRange appendAlertMsg = sheetsEp->appendValue(spreadSheetId, alertMessage, setSheetName);
    if appendAlertMsg is error {
        log:printError("Fail to send the alert to Spreadsheet. ", appendAlertMsg);
    }
    return alert;

}

# This function will call in the main method which includes all processed variables 
# of feed data to pass as parameters into `addnewfeed(p1,p2,...,pn)` function.
# Here p1, p2,..., pn are parameters of the function.
# 
# + return - Null or an error
public function tiFeeds() returns error? {
    int|string|decimal startingRowNum = 0;
    string lastColumn = "";
    int currentRowNumber = 0;
    (int|string|decimal)[][] rssFeedsInfo = [];
    string sheetEditingMode = "";
    string mlFilteringMode = "";

    // get the sheet's meta data. Sheet name :- 'Ti_feeds_metaData'.
    // meta data :- startingRowNum, lastColumn, sheetEditingMode, mlFilteringMode. 
    sheets:Range|error getRecordsRange = sheetsEp->getRange(spreadSheetId, sheetNameMetaData, "B1:B4");
    runtime:sleep(0.75);
    if getRecordsRange is error {
        log:printError(check setAlertMessage("Failed to get the sheet's metadata. " + getRecordsRange.toString()));
        return;
    } else {
        (int|string|decimal)[][] getVals = getRecordsRange.values;
        startingRowNum = getVals[0][0];
        lastColumn = getVals[1][0].toString();
        sheetEditingMode = getVals[2][0].toString();
        mlFilteringMode = getVals[3][0].toString();
    }

    if sheetEditingMode == "on" {
        log:printWarn(check setAlertMessage("Spreadsheet is in the Editing Mode."));
        return;
    }

    // get all Threat Intel sources metadata
    string setRange = "A" + startingRowNum.toString() + ":" + lastColumn.toString();
    sheets:Range|error getRecords = sheetsEp->getRange(spreadSheetId, sheetNameMetaData, setRange);
    runtime:sleep(0.75);
    if getRecords is error {
        log:printError(check setAlertMessage("Failed to get Threat Intel metadata. " + getRecords.toString()));
        return;
    } else {
        rssFeedsInfo = getRecords.values;
    }

    currentRowNumber = check int:fromString(startingRowNum.toString());
    string[] checkDuplicatesEndpoints = [];

    foreach (int|string|decimal)[] item in rssFeedsInfo {
        // checking the End Of Sheet(EOS)
        if item.indexOf("EOS") is int {
            return;
        }

        // setting up feed's primary details and validating 
        string feedName = item[0].toString();
        string feedEndPoint = item[1].toString();
        string feedLastRecUrl = item[2].toString();
        string feedLastRecTitelAndDes = item[3].toString();
        string feedShouldFiltered = item[4].toString();
        boolean isInvalidEndpoint = false;

        log:printInfo("---- " + feedName + " ----");

        // check feed endpoint is already using or not.
        if checkDuplicatesEndpoints.length() == 0 {
            checkDuplicatesEndpoints.push(feedEndPoint);
        } else {
            if checkDuplicatesEndpoints.indexOf(feedEndPoint) is int {
                log:printError(check setAlertMessage(feedName + " :- Feed endpoint is already using."));
                currentRowNumber = currentRowNumber + 1;
                continue;
            } else {
                checkDuplicatesEndpoints.push(feedEndPoint);
            }
        }

        json getClientData = {};
        http:Client httpClient; 
        http:Response response;
        do {
            httpClient = check new (feedEndPoint.toString());
            response = check httpClient->get("");
        } on fail {
            isInvalidEndpoint = true; 
        }

        if isInvalidEndpoint == true {
            log:printError(check setAlertMessage(feedName + " :- Invalid url or an error occurred  in httpClient module." + 
                " Please check the entered url in the Spreadsheet."));
            currentRowNumber = currentRowNumber + 1;
            continue;
        }

        if response.statusCode != http:STATUS_OK {
            log:printError(check setAlertMessage(feedName + " :- An error occurred  when fetching the details from the endpoint." + 
                " Please check the entered url in the Spreadsheet. StatusCode :- " + response.statusCode.toString()));
            currentRowNumber = currentRowNumber + 1;
            continue;
        } else {
            boolean formatIsXml = true;

            do {
                getClientData = check xmldata:toJson(check response.getXmlPayload());
            } on fail {
                formatIsXml = false;
            }

            if formatIsXml == false {
                do {
                    getClientData = check response.getJsonPayload();
                } on fail {
                    log:printError(check setAlertMessage(feedName + " :- Feed is not in the XML or Json format."));
                    currentRowNumber = currentRowNumber + 1;
                    continue;
                }
            }
        }

        if getClientData == "".toJson() {
            log:printError(check setAlertMessage(feedName + " :- The content is empty."));
            currentRowNumber = currentRowNumber + 1;
            continue;
        }

        // setting up feed item's meta data
        string titleTag = "";
        string dateTag = "";
        string descriptionTag = "";
        string urlTag = "";
        
        ItemDetails[] feedItems = [];
        boolean isErrorInFetchingDetails = false;

        do {
            xml? checkFormat = check xmldata:fromJson(getClientData);
            boolean formatISRss = checkFormat.toString().includes("rss+xml") || checkFormat.toString().includes("<rss ") &&
                checkFormat.toString().includes("<channel>") && checkFormat.toString().includes("<item>");
            boolean formatIsAtom = checkFormat.toString().includes("atom+xml") || checkFormat.toString().includes("<feed ") &&
                checkFormat.toString().includes("<entry>") && checkFormat.toString().includes("</entry>"); 
            boolean formatIsPreDefinedJson = checkFormat.toString().includes("<items>") && checkFormat.toString().includes("<date_published>") &&
                checkFormat.toString().includes("<summary>") && checkFormat.toString().includes("<url>");

            json[] getItemDetails = [];

            if formatISRss {
                getItemDetails = check getClientData.rss.channel.item.ensureType();
                titleTag = "title";
                dateTag = "pubDate";
                descriptionTag = "description";
                urlTag = "link";
            } else if formatIsAtom {
                getItemDetails = check getClientData.feed.entry.ensureType();
                titleTag = "title";
                dateTag = "updated";
                descriptionTag = "content";
                urlTag = "link";
            } else if formatIsPreDefinedJson {
                getItemDetails = check getClientData.items.ensureType();
                titleTag = "id";
                dateTag = "date_published";
                descriptionTag = "summary";
                urlTag = "url";
            } else {
                log:printError(check setAlertMessage(feedName + " :- Feed format is not 'rss' , 'atom' or 'defined json' format."));
                currentRowNumber = currentRowNumber + 1;
                continue;
            }

            int numOfItems = 0;
            foreach json getItems in getItemDetails {
                // get first 20 feed items
                if numOfItems < 20 {
                    map<json> singleItem = check getItems.ensureType();

                    // setting up the feed details
                    json setLink = check clearText(singleItem[urlTag]);
                    json setPubDate = check clearText(singleItem[dateTag]);
                    json setDiscription = check clearText(singleItem[descriptionTag]);
                    // reduce the content to first 150 words in the description.
                    setDiscription = reduceContent(setDiscription.toString(),150);
                    json setTitle = check clearText(singleItem[titleTag]);

                    if dateTag == "" {
                        string date = check getDate(0);
                        string time = check getTime(0);
                        setPubDate = date + " " + time;
                    }

                    ItemDetails setFeedItemDetails = {
                        link: setLink,
                        pubDate: setPubDate,
                        description: setDiscription,
                        title: setTitle
                    };
                    feedItems.push(setFeedItemDetails);
                }
                numOfItems = numOfItems + 1;
            }

        } on fail error e {
            log:printError(check setAlertMessage(feedName + " :- An error occurred when the fetching details." + 
                " Please check the Choreo logs"), e);
            isErrorInFetchingDetails = true;          
        }

        if isErrorInFetchingDetails {
            currentRowNumber = currentRowNumber + 1;
            continue;
        }

        string feedLastRecCellRange = "C" + currentRowNumber.toString() + ":" + "D" + currentRowNumber.toString();
        error? addFeed = addNewFeeds(feedName, feedItems, sheetsEp, feedLastRecCellRange , feedLastRecUrl,
            feedLastRecTitelAndDes, feedShouldFiltered, mlFilteringMode);
        if addFeed is error {
            log:printError(check setAlertMessage(feedName + " :- An error occurred in the feeds adding process."));
            currentRowNumber = currentRowNumber + 1;
            continue;
        }
        currentRowNumber = currentRowNumber + 1;
    }
}
