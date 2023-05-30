// Copyright (c) 2023, WSO2 Inc. (http://www.wso2.com). All Rights Reserved.
// 
// This software is the property of WSO2 Inc. and its suppliers, if any.
// Dissemination of any information or reproduction of any material contained
// herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
// You may not alter or remove any copyright or other notice from copies of this content.

import ballerina/lang.runtime;
import ballerina/log;
import ballerinax/googleapis.sheets;

configurable string refreshToken = ?;
configurable string clientId = ?;
configurable string clientSecret = ?;
configurable string spreadSheetId = ?;
configurable string sheetNameRecords = ?;
configurable string sheetNameMetaData = ?;
configurable string sheetNameCveIds = ?;
configurable string sheetNameAlerts = ?;
configurable string[] keyWordsLowerCase = ?;
configurable string mlModelBaseUrl = ?;
configurable string mlModelBearerToken = ?;

sheets:ConnectionConfig spreadSheetConfig = {
    auth: {
        clientId: clientId,
        clientSecret: clientSecret,
        refreshUrl: sheets:REFRESH_URL,
        refreshToken: refreshToken
    }
};
sheets:Client sheetsEp = check new (spreadSheetConfig);

public function main() returns error? {
    sheets:Range|error getLastExecuTimeAndStatus = sheetsEp->getRange(spreadSheetId, sheetNameAlerts, 
        LAST_EXECUTION_TIME_AND_STATUS_CELLS);
    runtime:sleep(1);
    if getLastExecuTimeAndStatus is sheets:Range {
        (int|string|decimal)[][] getVals = getLastExecuTimeAndStatus.values;
        string getLastExecuteTime = getVals[0][0].toString();
        string getStatus = getVals[0][1].toString();
        if getStatus == "Running" {
            log:printInfo(check setAlertMessage("Program is still running. Last execution started time :- " + getLastExecuteTime));
            string nextDate = check getDate(900);
            string nextTime = check getTime(900);
            string nextExecutionTime =string:'join(" at ",nextDate,nextTime) ;
            error? updateNextExecutionTime = sheetsEp->setCell(spreadSheetId, sheetNameAlerts, NEXT_EXECUTION_TIME_CELL, nextExecutionTime);
            if updateNextExecutionTime is error {
                log:printError("Failed to update the next execution time. ", updateNextExecutionTime);
                return;
            }
            return;
        }
    } else {
        log:printError("Failed to get the Cell details. ", getLastExecuTimeAndStatus);
        return;
    }

    string startedDate = check getDate(0);
    string startedTime = check getTime(0);
    string nextDate = check getDate(900);
    string nextTime = check getTime(900);

    string[][] entries = [[startedDate + " at " + startedTime, RUNNING_STATE, nextDate + " at " + nextTime]];
    sheets:Range range = {a1Notation: STATUS_RANGE, values: entries};

    error? setStatusRange = sheetsEp->setRange(spreadSheetId, sheetNameAlerts, range);
    if setStatusRange is error {
        log:printError("Failed to set status range. ", setStatusRange);
        return;
    }
    runtime:sleep(1);

    error? addFeedsToSpreadSheet = tiFeeds();
    if addFeedsToSpreadSheet is error {
        log:printError("Failed in feed details adding process.", addFeedsToSpreadSheet);
    } 

    error? updateStatusCell = sheetsEp->setCell(spreadSheetId, sheetNameAlerts, STATUS_CELL, EXECUTED_STATE);
    if updateStatusCell is error {
        log:printError("Unable to update the status cell. ", updateStatusCell);
        return;
    }
}
