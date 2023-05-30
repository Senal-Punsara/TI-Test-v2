// Copyright (c) 2023, WSO2 Inc. (http://www.wso2.com). All Rights Reserved.
// 
// This software is the property of WSO2 Inc. and its suppliers, if any.
// Dissemination of any information or reproduction of any material contained
// herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
// You may not alter or remove any copyright or other notice from copies of this content.

const LAST_EXECUTION_TIME_AND_STATUS_CELLS = "A3:B3";
const NEXT_EXECUTION_TIME_CELL = "C3";
const STATUS_RANGE = "A3:C3";
const STATUS_CELL = "B3";
const RUNNING_STATE = "Running";
const EXECUTED_STATE = "Executed";
const SHEET_METADATA_CELLS = "B1:B4";
enum ReturnValues {
    FILTERED = "1",
    NOTFILTERED = "0",
    ERROR = "-1"
}
