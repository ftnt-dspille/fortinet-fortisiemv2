"""
Copyright start
Copyright (C) 2008 - 2024 FortinetInc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end
"""

incident_schema = """<?xml version="1.0" encoding="UTF-8"?>
<Reports>
   <Report baseline="" rsSync="">
      <PatternClause>
         <SubPattern id="" name="">
            <SingleEvtConstr>(phEventCategory = 1) AND (phCustId IN (1))</SingleEvtConstr>
         </SubPattern>
      </PatternClause>
      <SelectClause>
      <AttrList>{select_clause}</AttrList>
      </SelectClause>
        <OrderByClause>
            <AttrList>phRecvTime DESC</AttrList>
        </OrderByClause>
      <SyncOrgs />
      <ReportInterval>{time_duration}</ReportInterval>
   </Report>
</Reports>"""

report_schema = """<Reports><Report group="report">
     <Name></Name>
     <Description></Description>
     <CustomerScope groupByEachCustomer="false">
          <Include all="true"/>
          <Exclude/>
     </CustomerScope>
     <SelectClause>
          <AttrList>{AttrList}</AttrList>
     </SelectClause>
     <OrderByClause>
          <AttrList>{orderby}</AttrList>
     </OrderByClause>
     <ReportInterval>
         {time_duration}
     </ReportInterval>
     <PatternClause>
          <SubPattern id="Reports" name="Reports">
               <SingleEvtConstr>{conditions}</SingleEvtConstr>
               <GroupByAttr>{groupby}</GroupByAttr>
          </SubPattern>
     </PatternClause>
     <SyncOrgs/>
    </Report>
</Reports>"""

events_schema = """<?xml version="1.0" encoding="utf-8"?>
            <Reports>
                <Report id="" group="">
                    <Name/>
                    <description/>
                    <SelectClause numEntries="All">
                        <AttrList/>
                    </SelectClause>
                    <PatternClause window="3600">
                        <SubPattern displayName="" name="">
                            <SingleEvtConstr> {event_filter} </SingleEvtConstr>
                        </SubPattern>
                    </PatternClause>
                </Report>
            </Reports>"""

discover_device_schema = """<discoverRequest>
                                <type>{disc_type}</type> 
                                <includeRange>{include_ip}</includeRange> 
                                <excludeRange>{exclude_ip}</excludeRange> 
                                <noPing>{noping}</noPing>
                                <onlyPing>{onlyping}</onlyPing> 
                            </discoverRequest>"""



schema_by_event_id = """<?xml version="1.0" encoding="UTF-8"?>
<Reports>
    <Report baseline="" rsSync="">
        <PatternClause>
            <SubPattern id="" name="">
                <SingleEvtConstr>{eventId}</SingleEvtConstr>
            </SubPattern>
        </PatternClause>
        <SelectClause>
            <AttrList>{select_clause}</AttrList>
        </SelectClause>
        <OrderByClause>
            <AttrList>phRecvTime DESC</AttrList>
        </OrderByClause>
        <SyncOrgs/>
        <ReportInterval>{time_duration}</ReportInterval>
    </Report>
</Reports>"""

search_event_schema = """<?xml version="1.0" encoding="UTF-8"?>
<Reports>
    <Report baseline="" id="" rsSync="">
        <Name>{reportName}</Name>
        <Description></Description>
        <CustomerScope groupByEachCustomer="false">
            <Include all="true"/>
            <Exclude/>
        </CustomerScope>
        <PatternClause>
            <SubPattern id="" name="">
                <SingleEvtConstr>{queryString}</SingleEvtConstr>
            </SubPattern>
        </PatternClause>
        <SelectClause>
            <AttrList>{select_clause}</AttrList>
        </SelectClause>
        <OrderByClause>
            <AttrList>phRecvTime DESC</AttrList>
        </OrderByClause>
        <ReportInterval>
            {time_duration}
        </ReportInterval>
    </Report>
</Reports>"""
