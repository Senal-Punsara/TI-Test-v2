// Copyright (c) 2023, WSO2 Inc. (http://www.wso2.com). All Rights Reserved.
// 
// This software is the property of WSO2 Inc. and its suppliers, if any.
// Dissemination of any information or reproduction of any material contained
// herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
// You may not alter or remove any copyright or other notice from copies of this content.

# capturing following attributes from a single feed which in 
# RssfeedItems record.
# 
# + link - link to the specific feed.
# + description - description of feed.
# + title - title of feed.
# + pubDate - published date of feed.
public type ItemDetails record {
    json  link;
    json  description;
    json  title;
    json  pubDate;
};

# this record includes all feeds in a threat intel's rss feed. Some RSS feeds include their feeds in
# the array which named as 'items' and some include feeds in the array which named as
# 'item'. So two ItemDetails records are created as follows to capture the feeds.
# 
# + items - includes all feeds in a specific RSS feed (if array named as 'items' in RSS feed). 
# + item - includes all feeds in a specific RSS feed (if array named as 'items' in RSS feed). 
public type RssfeedItems record {
    ItemDetails[] items = [];
    ItemDetails[] item = [];  
};

# this record includes variables which are needed to capture the RSS feed in a specific 
# threat intelligence.
#
# + getClientData - captured RSS feed in xml format. 
# + getClientDataJsonFormat - captured RSS feed in json format.  
# + temp - temporary variable to record feeds after converting (if feed in the xml format) and  traversing 
#          into specific section in the converted json type of RSS feed. 
# + getAllfeeds - get relevant feed data from the json type variable to RssfeedItems record type.  
# + addFeed - addnewfeed() function will be assigned to this variable.
public type threatIntelRssFeed record {
    xml  getClientData;
    json getClientDataJsonFormat;
    json temp;
    RssfeedItems getAllfeeds;
    error? addFeed;    
};

