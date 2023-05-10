// Copyright (c) 2023, WSO2 Inc. (http://www.wso2.com). All Rights Reserved.
// 
// This software is the property of WSO2 Inc. and its suppliers, if any.
// Dissemination of any information or reproduction of any material contained
// herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
// You may not alter or remove any copyright or other notice from copies of this content.

import ballerinax/googleapis.sheets;
import ballerina/regex;
import ballerina/time;
import ballerina/log;
import ballerina/http;
import ballerina/xmldata;
import ballerina/io;
import ballerina/lang.runtime;
import ballerina/lang.'int;

# calling machine learing model api for filtering 
#
# + text - string which need to be filtered.
# + return - a string  ('relevent' or 'not_relevent')
public function mlFilteringModel(string text) returns int|error {

    string[] replaceChar = ["\\n", "[^a-zA-Z0-9\\s]"];
    string cleanText = text;
    foreach string item in replaceChar {
        cleanText = regex:replaceAll(cleanText, item, "");
    }
      
    http:Client httpClientML = check new (mlModelBaseUrl);

    http:Request reqML = new ();
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
    reqML.addHeader("Authorization", "Bearer "+mlModelBearerToken);
    reqML.addHeader("Content-Type","application/json");

    http:Response response = check httpClientML->post(path = "", message = (reqML));
    if (response.statusCode != 200) {
        log:printError("ML Api error. Status code:- " + response.statusCode.toString());
        return -1;
    } else {
        json getResponse =check response.getJsonPayload();
       
        json getResult = check getResponse.Results;
        json[] WebServiceOutput0 = check getResult.WebServiceOutput0.ensureType();
        json temp = WebServiceOutput0[0];
        map<json>label = <map<json>>temp;
        json getLabel = label["Scored Labels"];
        if getLabel == "relevent" {
            return 1;
        } else {
            return 0;
        }
    }
}

public function similarity(string s1, string s2) returns float {
    int len1 = s1.length();
    int len2 = s2.length();

    // Initialize a 2D array with dimensions (len1+1) x (len2+1)
    int[][] matrix = [];
   
    // Fill in the first row and column of the matrix
    foreach int i in 0...len1 {
        matrix[i][0] = i;
    }
    foreach int j in 0...len2 {
        matrix[0][j] = j;
    }
  
    // Fill in the rest of the matrix
    foreach int i in 1...len1 {
        foreach int j in 1...len2 {
            if (s1[i - 1] == s2[j - 1]) {
                matrix[i][j] = matrix[i - 1][j - 1];
            } else {
                matrix[i][j] = 1 + int:min(matrix[i - 1][j], matrix[i][j - 1], matrix[i - 1][j - 1]);
            }
        }
    }

    // The Levenshtein Distance is the value in the bottom-right cell of the matrix
    // The similarity score is the inverse of the Levenshtein Distance, normalized by the length of the longer string
    
    float similarityScore = <float>(1-<float>(matrix[len1][len2]) /<float>(int:max(len1,len2)));

    return similarityScore;
}

# function which filtering feeds according to keywords,using machine learning model and CVE numbers.
#
# + feedDetails - a record which includes all feed details of a specific threat intel.  
# + sheetsEp - sheet client endpoint. 
# + feedShouldFiltered - feed should be filtered or not.
# + mlFilteringMode - feed should be filtered using mlModel or not.
# + return - 0 , 1, -1.
public function filteringFeeds(json feedDetails, sheets:Client sheetsEp, string feedShouldFiltered, string mlFilteringMode)
    returns int|error {
    int filteringFlag = 0;
    string filteringString = ((check feedDetails.link).toString() + " " + (check feedDetails.title).toString()
        + " " + (check feedDetails.description).toString()).toLowerAscii();
    //filteringString includes feed link + title + description in lowercase.

    boolean mainFiltering = false;
    int|error mlFiltered = 0;
    boolean cveFiltered = false;
    int noKeyWord = 0;
    if feedShouldFiltered == "yes" {
        //filtering the feed according to keywords. if filteringString includes
        //one of key words in keyWords array then mainFiltering become true. 
        foreach string word in keyWordsLowerCase {
            if filteringString.includes(word) {
                if mlFilteringMode == "on" {
                    string text = ((check feedDetails.title).toString() + " " + (check feedDetails.description).toString());
                    mlFiltered = mlFilteringModel(text);
                    runtime:sleep(0.75);
                    if mlFiltered is error || mlFiltered == -1 {
                        log:printError("error in ml filtering ");
                        return -1;
                    } else if mlFiltered == 1 {
                        mainFiltering = true;
                    }

                } else if mlFilteringMode == "off" {
                    mainFiltering = true;
                } else {
                    log:printError("ML Filtering mode value is not either 'on' or 'off'. Check the Spread Sheet.");
                    return -1;
                }
                break;
            } else {
                noKeyWord = noKeyWord + 1;
            }
        }
        if noKeyWord == keyWordsLowerCase.length() {

        }
    } else if feedShouldFiltered == "no" {
        mainFiltering = true;
    }

    //filtering the feed according to  cve numbers. if filteringString 
    //includes new cve numbers cveFiltered become true. 
    if filteringString.includes("cve-") {

        string[] cveNumArray = [];
        // the array which will  include all the cve numbers which are included in the relevant feed.

        regex:Match[] cveNumbers = regex:searchAll(filteringString, "cve-[0-9]{4}-[0-9]+");
        //extracting all cve numbers in the filteringString into cveNumbers array.

        foreach int x in 0 ... cveNumbers.length() - 1 {
            if cveNumArray.indexOf(cveNumbers[x]["matched"]) !is int {
                cveNumArray.push(cveNumbers[x]["matched"]);
            }
        }

        (string|int|decimal)[] cveNums = [];
        //this is the variable which will be assigned the all cve numbers which are in the spreadsheet.

        string[] addCevNumbers = [];
        //will add cve numbers from cveNumArray to addCevNumbers array if those will not include in cveNums;

        int countMatchedCve = 0;
        //this is the variable which will count how many 

        //getting colunm A values from the spreadsheet. 
        //name of the spreadsheet 'TI_Solution'. name of the subsheet 'CVE_ids' 
        sheets:Column|error column = sheetsEp->getColumn(spreadSheetId, sheetNameCveIds, "A");
        runtime:sleep(1);
        if column is sheets:Column {
            //assigning column A values in the spreadsheet to cveNums.
            //name of the spreadsheet 'TI_Solution'. name of the subsheet 'CVE_ids' 
            cveNums = column.values;

            //checking that there are any cve numbers in cveNumArray which already contains in cveNums.
            foreach string item in cveNumArray {
                if cveNums.indexOf(item) !is int {
                    //if the current item (cve number) is not in the cveNums push it to addCevNumbers.
                    addCevNumbers.push(item);

                } else {
                    //if the current item (cve number) is  in the increase the value of countMatchedCve by 1 .
                    countMatchedCve = countMatchedCve + 1;
                }
            }

            if addCevNumbers.length() != 0 {
                //new cve numbers are found.
                cveFiltered = true;

                foreach string item in addCevNumbers {
                    string[] temp = [];
                    temp.push(item);
                    string setDate = getDate(0);
                    temp.push(setDate);
                    error? appendCveNumbers = sheetsEp->appendRowToSheet(spreadSheetId, sheetNameCveIds, temp);
                    runtime:sleep(0.75);
                    if appendCveNumbers is error {
                        log:printError("error occurs when sending cve numbers to the spread shaeet.");
                        return -1;

                    }
                }
            }

        }
        else {
            log:printError("error occurs when getting cve numbers from the spread shaeet.");
            return -1;
        }

    }

    if mainFiltering == true && filteringString.includes("cve-") == false {
        //if feed has a key word which in keyWords array and not includes 'cve-' then filteringFlag = 1;
        filteringFlag = 1;
    } else if mainFiltering == true && filteringString.includes("cve-") == true {
        if cveFiltered == true {
            //if feed has a key word which in keyWords array and feed has new cve numbers then filteringFlag = 1;
            filteringFlag = 1;
        }
    }

    return filteringFlag;
}

# process of adding new feeds. created this function to improve the code readability.
#
# + nameOfFeed - name of the feed. eg:- hackernews, bleeping computer.   
# + feedDetails - a record which includes all feed details of a specific threat intel.   
# + sheetsEp - sheet client endpoint.   
# + feedLastUrlCell - cell of the url which is recorded as the latest url of a feed in the spread sheet.  
# + feedShouldFiltered - feed should be filtered or not
# + mlFilteringMode - feed should be filtered using mlModel or not.
# + return - null or error.
public function newFeedAddingProcess(string nameOfFeed, ItemDetails[] feedDetails, sheets:Client sheetsEp,
        string feedLastUrlCell, string feedShouldFiltered, string mlFilteringMode) returns error? {

    //new feeds will be added to the records.
    string[][] records = [];

    int|string|decimal lastRecFeedUrl;

    //get the url of the latest record of relevant feed from the spreadsheet.
    sheets:Cell|error getLastRecFeedUrl = sheetsEp->getCell(spreadSheetId, sheetNameMetaData, feedLastUrlCell);
    runtime:sleep(0.75);
    if getLastRecFeedUrl is sheets:Cell {
        lastRecFeedUrl = getLastRecFeedUrl.value;

    } else {
        log:printError(setAlertMessage(nameOfFeed + " :- Cannot get the last record's url. " + getLastRecFeedUrl.toString()));
        return;
    }

    boolean isErrorInFiltering = false;

    foreach int i in 0 ..< feedDetails.length() {

        //if a threat intel is new to the system 
        if lastRecFeedUrl == "new_feed" {

            error? setLastRecord = sheetsEp->setCell(spreadSheetId, sheetNameMetaData, feedLastUrlCell, feedDetails[0].link.toString());
            runtime:sleep(0.75);
            if setLastRecord is error {
                log:printError(setAlertMessage(nameOfFeed + " :- Cannot add the TI feed. " + setLastRecord.toString()));
                return;
            }
            log:printInfo(setAlertMessage(nameOfFeed + " TI feed is added."));
            return;
        }

        //checking latest feed url in feedDetails is equal with lastRecFeedUrl
        if feedDetails[i].link.toString() == lastRecFeedUrl || similarity(feedDetails[i].link.toString(),lastRecFeedUrl.toString())>0.85 {

            if i == 0 {
                //this means Last record  of relevant feed is still the latest feed.
                log:printInfo("up to date");
                return;
            } else {

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
                        error? appendRow = sheetsEp->appendRowToSheet(spreadSheetId, sheetName, vals);
                        runtime:sleep(0.75);
                        if appendRow is error {
                            log:printError(setAlertMessage(nameOfFeed + " :- error occurs when sending data to the spread sheet. "));
                            //updating the latest record as the last record. index 0 includes the newest record!
                            error? setLastRecord = sheetsEp->setCell(spreadSheetId, sheetNameMetaData, feedLastUrlCell, feedDetails[0].link.toString());
                            runtime:sleep(0.75);
                            if setLastRecord is error {
                                log:printError(setAlertMessage(nameOfFeed + ":- Cannot update the lastest record. " + setLastRecord.toString()));
                                return;
                            }
                            log:printInfo("Last record is updated.");

                            return;
                        }
                    }

                    log:printInfo(records.length().toString() + " records are send to the google sheet (1st)");

                } else {
                    log:printError(setAlertMessage(nameOfFeed + " :- Error in the filtering process. Please check choreo logs for further information."));

                }

                //updating the latest record as the last record. index 0 includes the newest record!
                error? setLastRecord = sheetsEp->setCell(spreadSheetId, sheetNameMetaData, feedLastUrlCell, feedDetails[0].link.toString());
                runtime:sleep(0.75);
                if setLastRecord is error {
                    log:printError(setAlertMessage(nameOfFeed + ":- Cannot update the lastest record. " + setLastRecord.toString()));
                    return;
                }
                log:printInfo("Last record is updated.");
                return;
            }

        } else {

            //assign the i th index of feedDetail's data into passData json variable.
            json passData = {
                pubDate: feedDetails[i].pubDate,
                title: feedDetails[i].title,
                link: feedDetails[i].link,
                description: feedDetails[i].description
            };
            //get the return value of filteringFeeds function by passing passData json variable.
            //(which includes i th index of feedDetail's data)

            int|error isFiltered = filteringFeeds(passData, sheetsEp, feedShouldFiltered, mlFilteringMode);

            if isFiltered == 1 {
                //if isFiltered == 1 ,which means feed(i th index of feedDetail's data) is filtered. 
                //So it can add to the records array.
                string[] values = [
                    nameOfFeed,
                    (feedDetails[i].pubDate).toString(),
                    (feedDetails[i].title).toString(),
                    (feedDetails[i].link).toString(),
                    (feedDetails[i].description).toString()
                ];

                //push the filtered feed into records array.
                records.push(values);
            } else if isFiltered == -1 || isFiltered is error {
                log:printError("filtering error ");
                isErrorInFiltering = true;

            }

        }

    }

    //this happens when after traversing the whole array and couldn't find the url which recorded as the
    //last record of the relevant feed in the "last_record_of_feeds" sheet.
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
            error? appendRow = sheetsEp->appendRowToSheet(spreadSheetId, sheetName, vals);
            runtime:sleep(0.75);
            if appendRow is error {
                log:printError(setAlertMessage(nameOfFeed.toString() + " :- error occurs when sending data to the spread sheet. " + appendRow.toString()));
                //updating the latest record as the last record. index 0 includes the newest record!
                error? setLastRecord = sheetsEp->setCell(spreadSheetId, sheetNameMetaData, feedLastUrlCell, feedDetails[0].link.toString());
                runtime:sleep(0.75);
                if setLastRecord is error {
                    log:printError(setAlertMessage(nameOfFeed + ":- Cannot update the lastest record. " + setLastRecord.toString()));
                    return;
                }
                log:printInfo("Last record is updated.");

                return;
            }
        }

        log:printInfo(nameOfFeed.toString() + ":- " + records.length().toString() + " records are send to the google sheet (2nd)");

    } else {
        log:printError(setAlertMessage(nameOfFeed.toString() + ":- error in the filtering. Check Choreo logs."));

    }

    //updating the latest record as the last record. index 0 includes the newest record!
    error? setLastRecord = sheetsEp->setCell(spreadSheetId, sheetNameMetaData, feedLastUrlCell, feedDetails[0].link.toString());
    runtime:sleep(0.75);
    if setLastRecord is error {
        log:printError(setAlertMessage(nameOfFeed + ":- Cannot update the lastest record. " + setLastRecord.toString()));
        return;
    }
    log:printInfo("Last record is updated.");
    return;
}

# returns the current date which is customized.
#
# + seconds - time ajustment.
# + return - current date `mm/dd/yyyy` as a string.
public function getDate(decimal seconds) returns string {
    //19800 sec = 05 hours 30 mins
    time:Utc utc = time:utcAddSeconds(time:utcNow(), 19800 + seconds);
    time:Civil civil = time:utcToCivil(utc);
    json getTime = civil.toJson();
    map<json> mapDate = <map<json>>getTime;
    string date = mapDate["month"].toString() + "/" + mapDate["day"].toString() + "/"
        + mapDate["year"].toString();

    return date;
}

# returns the current time which is customized.
#
# + seconds - time ajustment 
# + return - current time `hh:MM:ss` as a string.
public function getTime(decimal seconds) returns string {
    //19800 sec = 05 hours 30 mins
    time:Utc utc = time:utcAddSeconds(time:utcNow(), 19800 + seconds);
    time:Civil civil = time:utcToCivil(utc);
    json getTime = civil.toJson();
    map<json> mapTime = <map<json>>getTime;
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

# Description
#
# + text - content which needs to clean
# + return - Return the content which is cleaned.
public function clearText(json text) returns string|error {
    string theText = "";
    string[][] replaceChar = [
        ["\\[", ""],["\\]", ""],["\",\"", ""],
        ["\"", ""],["&lt;", "<"],["&gt;", ">"],
        ["<.*?>", ""],["&amp;", "&"],["#38;", ""],
        ["nbsp;", "'"],["&.*?;", ""]
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

public function setAlertMessage(string alert) returns string {
    string dateAlert = getDate(0);
    string timeAlert = getTime(0);
    string setAlertTime = dateAlert + " at " + timeAlert;
    string[] alertMessage = [setAlertTime, alert];
    error? appendAlertMsg = sheetsEp->appendRowToSheet(spreadSheetId, sheetNameAlerts, alertMessage);
    if appendAlertMsg is error {
        log:printError(appendAlertMsg.toString());
    }
    return alert;

}

# this function will call in the main method which includes all processed variables 
# of feed data to pass as parameters into addnewfeed(p1,p2,....pn) function.
# (here p1,p2,pn refers parameters of the function)
# + return - null or error.
public function tiFeeds() returns error? {
    io:println(getDate(0));

    int|string|decimal startingRowNum = 0;
    string lastColumn = "";
    int currentRowNumber = 0;
    (int|string|decimal)[][] rssFeedsInfo = [];
    string sheetEditingMode = "";
    string mlFilteringMode = "";

    //get the sheet's meta data. Sheet name :- 'Ti_feeds_metaData'.
    //meta data :- startingRowNum, lastColumn, sheetEditingMode, mlFilteringMode. 
    sheets:Range|error getRecordsRange = sheetsEp->getRange(spreadSheetId, sheetNameMetaData, "B1:B4");
    runtime:sleep(0.75);
    if getRecordsRange is error {
        log:printInfo(setAlertMessage("Cannot get sheet's meta data." + getRecordsRange.toString()));
        return;
    } else {
        (int|string|decimal)[][] getVals = getRecordsRange.values;
        startingRowNum = getVals[0][0];
        lastColumn = getVals[1][0].toString();
        sheetEditingMode = getVals[2][0].toString();
        mlFilteringMode = getVals[3][0].toString();
    }

    if sheetEditingMode == "on" {
        log:printInfo(setAlertMessage("Spread sheet is in the Editing Mode"));

        return;
    }

    //get all Threat Intel sources feed records
    string setRange = "A" + startingRowNum.toString() + ":" + lastColumn.toString();
    sheets:Range|error getRecords = sheetsEp->getRange(spreadSheetId, sheetNameMetaData, setRange);
    runtime:sleep(0.75);
    if getRecords is error {
        log:printInfo(getRecords.toString());
        return;
    } else {
        rssFeedsInfo = getRecords.values;
    }

    currentRowNumber = check int:fromString(startingRowNum.toString());
    string[] checkDuplicatesEndpoints = [];
    foreach (int|string|decimal)[] item in rssFeedsInfo {

        //checking the End Of Sheet(EOS)
        if item.indexOf("EOS") is int {
            return;
        }

        //setting up feed's primary details and validating 
        string feedName = item[0].toString();
        string feedEndPoint = item[1].toString();
        string feedShouldFiltered = item[3].toString();
        boolean isInvalidEndpoint = false;

        log:printInfo("---- " + feedName + " ----");

        //check feed endpoint is already using or not.
        if checkDuplicatesEndpoints.length() == 0 {
            checkDuplicatesEndpoints.push(feedEndPoint);
        } else {
            if checkDuplicatesEndpoints.indexOf(feedEndPoint) is int {
                log:printError(setAlertMessage(feedName + " :- feed endpoint is already using."));
                currentRowNumber = currentRowNumber + 1;
                continue;
            } else {
                checkDuplicatesEndpoints.push(feedEndPoint);
            }
        }

        json getClientData = {};
        io:println(feedEndPoint.toString());
        http:Client httpClient; 
        http:Response response;
        do {
            httpClient = check new (feedEndPoint.toString());
            response = check httpClient->get("");
        } on fail {
            isInvalidEndpoint = true;
        }

        if isInvalidEndpoint == true {
            log:printError(setAlertMessage(feedName + " :- Invalid url. Please check the entered url in the spread sheet."));
            currentRowNumber = currentRowNumber + 1;
            continue;
        }

        if response.statusCode != 200 {
            log:printError(setAlertMessage(feedName + " :- Error occurs when fetching the details from the endpoint. StatusCode :- "
                + response.statusCode.toString()));

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
                    log:printError(setAlertMessage(feedName + " :- Feed is not in XML or Json format"));
                    currentRowNumber = currentRowNumber + 1;
                    continue;
                }
            }

        }
        if getClientData == "".toJson() {

            log:printError(setAlertMessage(feedName + " :- Content is empty"));
            currentRowNumber = currentRowNumber + 1;
            continue;
        }

        //setting up field access tags and feed item's meta data
        string[] fieldAccesTags = [];
        string titleTag = "";
        string dateTag = "";
        string descriptionTag = "";
        string urlTag = "";

        xml? checkFormat = check xmldata:fromJson(getClientData);

        if checkFormat.toString().includes("rss+xml") || checkFormat.toString().includes("<rss ") &&
        checkFormat.toString().includes("<channel>") && checkFormat.toString().includes("<item>") {
            fieldAccesTags = ["rss", "channel", "item", "EOL"];
            titleTag = "title";
            dateTag = "pubDate";
            descriptionTag = "description";
            urlTag = "link";
        } else if checkFormat.toString().includes("atom+xml") || checkFormat.toString().includes("<feed ") &&
        checkFormat.toString().includes("<entry>") && checkFormat.toString().includes("</entry>") {
            fieldAccesTags = ["feed", "entry", "EOL"];
            titleTag = "title";
            dateTag = "updated";
            descriptionTag = "content";
            urlTag = "link";
        } else if checkFormat.toString().includes("<items>") && checkFormat.toString().includes("<date_published>") &&
        checkFormat.toString().includes("<summary>") && checkFormat.toString().includes("<url>") {
            fieldAccesTags = ["items", "EOL"];
            titleTag = "id";
            dateTag = "date_published";
            descriptionTag = "summary";
            urlTag = "url";
        } else {
            log:printError(setAlertMessage(feedName + " :- Feed format is not 'rss' , 'atom' or 'other/json'"));
            currentRowNumber = currentRowNumber + 1;
            continue;
        }

        json? AccessingFeild = {};
        json[] getItemDetails = [];

        //get the index of 'EOL' in fieldAccesTags. (EOL - End Of Line)
        int getLastItemIndex = <int>fieldAccesTags.indexOf("EOL");
        boolean isErrorInFeildAccessing = false;
        //get the feed item details into getItemDetails array
        do {

            if getLastItemIndex > 1 {

                AccessingFeild = (<map<json>>getClientData)[fieldAccesTags[0]];

                if (getLastItemIndex == 2) {
                    //do nothing
                } else {
                    foreach int i in 1 ... getLastItemIndex - 2 {
                        AccessingFeild = (<map<json>>AccessingFeild)[fieldAccesTags[i]];

                    }
                }

                getItemDetails = check (<map<json>>AccessingFeild)[fieldAccesTags[getLastItemIndex - 1]].ensureType();

            } else if getLastItemIndex == 1 {
                AccessingFeild = <map<json>>getClientData;
                getItemDetails = check (<map<json>>AccessingFeild)[fieldAccesTags[0]].ensureType();
            } else {
                getItemDetails = check getClientData.ensureType();
            }
        } on fail {
            isErrorInFeildAccessing = true;
        }

        if isErrorInFeildAccessing == true {
            log:printError(setAlertMessage(feedName + " :- mismatch with the feild accessing tags or content is empty"));
            currentRowNumber = currentRowNumber + 1;
            continue;

        } else {
            ItemDetails[] feedItems = [];
            int numOfItems = 0;
            foreach json getItems in getItemDetails {
                //get first 20 feed items
                if numOfItems <= 20 {
                    map<json> singleItem = <map<json>>getItems;
                    // setting up feed details
                    json setLink = singleItem[urlTag];
                    json setPubDate = singleItem[dateTag];
                    json setDiscription = singleItem[descriptionTag];
                    json setTitle = singleItem[titleTag];
                    if dateTag == "N/A" {
                        string date = getDate(0);
                        string time = getTime(0);
                        setPubDate = date + " " + time;
                    }

                    //clean the feed details;
                    string|error cleanLink = clearText(setLink);
                    if cleanLink is error {
                        log:printError("error in getting the link");
                    } else {
                        setLink = cleanLink;
                    }

                    string|error cleanPubDate = clearText(setPubDate);
                    if cleanPubDate is error {
                        log:printError("error in getting the Published Date");
                    } else {
                        setPubDate = cleanPubDate;
                    }

                    string|error cleanDiscription = clearText(setDiscription);
                    if cleanDiscription is error {
                        log:printError("error in getting the description");

                    } else {
                        //reduce the content to first 500 words.
                        string[] splitDes = regex:split(cleanDiscription, " ");
                        int countWords = 0;
                        string reduceContentOfDes = "";
                        foreach string word in splitDes {
                            if countWords <= 500 {
                                reduceContentOfDes = reduceContentOfDes + " " + word;
                            }
                            countWords = countWords + 1;
                        }
                        setDiscription = reduceContentOfDes;
                    }

                    string|error cleanTitle = clearText(setTitle);
                    if cleanTitle is error {
                        log:printError("error in getting the title");
                    } else {
                        setTitle = cleanTitle;
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

            string feedLastUrlCell = "C" + currentRowNumber.toString();
            error? addFeed = newFeedAddingProcess(feedName, feedItems, sheetsEp, feedLastUrlCell, feedShouldFiltered, mlFilteringMode);
            if addFeed is error {
                log:printError(setAlertMessage(feedName + " :- error in adding feeds process"));
                currentRowNumber = currentRowNumber + 1;
                continue;
            }
        }
        currentRowNumber = currentRowNumber + 1;
    }

}

