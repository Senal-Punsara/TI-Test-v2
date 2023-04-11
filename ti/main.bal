// Copyright (c) 2023, WSO2 Inc. (http://www.wso2.com). All Rights Reserved.
// 
// This software is the property of WSO2 Inc. and its suppliers, if any.
// Dissemination of any information or reproduction of any material contained
// herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
// You may not alter or remove any copyright or other notice from copies of this content.

import ballerinax/googleapis.sheets;
import ballerina/lang.runtime;
import ballerina/log;

configurable string refreshToken = ?;
configurable string clientId = ?;
configurable string clientSecret = ?;
configurable string spreadSheetId = ?;
configurable string sheetName = ?;
configurable string sheetNameMetaData = ?;
configurable string sheetNameCveIds = ?;
configurable string sheetNameAlerts = ?;
configurable string[] keyWordsLowerCase = ?;
configurable string mlModelBaseUrl = ?;
configurable string mlModelTokenUrl = ?;
configurable string mlModelClientId = ?;
configurable string mlModelClientSecret = ?;
configurable string mlModelApiKey = ?;


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
    string statusCellRange = "A3:B3";
    sheets:Range|error getStatusRange = sheetsEp->getRange(spreadSheetId, sheetNameAlerts, statusCellRange);
    runtime:sleep(1);
    if getStatusRange is sheets:Range {
         (int|string|decimal)[][] getVals = getStatusRange.values;
         string getLastExecuteTime = getVals[0][0].toString();
          string getStatus = getVals[0][1].toString();
        if getStatus == "Running" {
            log:printInfo(setAlertMessage("Program is still running. Execution started time :- " + getLastExecuteTime));
            string nextExecutionTimeCell = "C3";
            string nextDate = getDate(900);
            string nextTime = getTime(900);
            string nextExecutionTime = nextDate + " at " + nextTime;
            error? updateNextExecutionTime = sheetsEp->setCell(spreadSheetId, sheetNameAlerts, nextExecutionTimeCell, nextExecutionTime);
            if updateNextExecutionTime is error {
                log:printInfo(updateNextExecutionTime.toString());
                return;
            }
            return;
        }
    } else {
        log:printError("Cannot get the getStatusRange. " + getStatusRange.toString());

        return;
    }

    string updateStatusRange = "A3:C3";
    string startedDate = getDate(0);
    string startedTime = getTime(0);
    string nextDate = getDate(900);
    string nextTime = getTime(900);
    string status = "Running";
    string[][] entries = [[startedDate + " at " + startedTime, status, nextDate + " at " + nextTime]];
    sheets:Range range = {a1Notation: updateStatusRange, values: entries};
    error? setupdateStatusRange = sheetsEp->setRange(spreadSheetId, sheetNameAlerts, range);
    if setupdateStatusRange is error {
        log:printInfo(setupdateStatusRange.toString());
        return;
    }
    runtime:sleep(1);
    error? addFeedsToSpreadSheet = tiFeeds();
    if addFeedsToSpreadSheet is error {
        log:printError("unsuccess");
    } 
    string statusCell = "B3";
    error? updateStatusCell = sheetsEp->setCell(spreadSheetId, sheetNameAlerts, statusCell, "Executed");
    if updateStatusCell is error {
        log:printError("Unable to update the status cell "+updateStatusCell.toString());
        return;
    }
}
