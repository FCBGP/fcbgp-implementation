-- @author      basilguo@163.com
-- @version     0.0.1
-- @description Parse Forwarding Commitment - Binding Message
-- @usage       Adding this script to the lua script's directory.
--      Following this steps: "Help->About->Folders->Personal Lua Plugins"


-- create a Proto object
local fcbm_proto = Proto("fcbm", "FCBM Protocol")

-- create ProtoField Objects
fcbm_version = ProtoField.int8("fcbm.fcbm_version", "Protocol Version", base.DEC)
msg_type = ProtoField.int8("fcbm.msg_type", "Message Type", base.DEC)
length = ProtoField.int16("fcbm.length", "Length", base.DEC)

ipversion = ProtoField.int8("fcbm.ipversion", "IP Version", base.DEC)
node_type = ProtoField.int8("fcbm.node_type", "Node Type", base.DEC)
action = ProtoField.int8("fcbm.action", "Node Action", base.DEC)
fc_num = ProtoField.int8("fcbm.fc_num", "FC Number", base.DEC)
srcip_num = ProtoField.int8("fcbm.srcip_num", "Source Prefix Number", base.DEC)
dstip_num = ProtoField.int8("fcbm.dstip_num", "Destination Prefix Number", base.DEC)
siglen = ProtoField.int16("fcbm.siglen", "Signature Length", base.DEC)
local_asn = ProtoField.int32("fcbm.local_asn", "Local AS Number", base.DEC)
version = ProtoField.int32("fcbm.version", "Version", base.DEC)
subversion = ProtoField.int32("fcbm.subversion", "SubVersion", base.DEC)

srcip_prefix = ProtoField.bytes("fcbm.srcip.prefix", "Source Prefix", base.SPACE)
srcip_prefixlen = ProtoField.bytes("fcbm.srcip.prefixlen", "Source Prefix Length", base.SPACE)
dstip_prefix = ProtoField.bytes("fcbm.dstip.prefix", "Destination Prefix", base.SPACE)
dstip_prefixlen = ProtoField.bytes("fcbm.dstip.prefixlen", "Destination Prefix Length", base.SPACE)

pasn = ProtoField.int32("fcbm.fclist.pasn", "Previous ASN", base.DEC)
casn = ProtoField.int32("fcbm.fclist.casn", "Current ASN", base.DEC)
nasn = ProtoField.int32("fcbm.fclist.nasn", "Nexthop ASN", base.DEC)
fcski = ProtoField.bytes("fcbm.fclist.ski", "Subject Key Identity", base.SPACE)
algo_id = ProtoField.int8("fcbm.fclist.algo_id", "Algorithm Identity", base.DEC)
flags = ProtoField.int8("fcbm.fclist.flags", "Flags", base.DEC)
fcsiglen = ProtoField.int16("fcbm.fclist.siglen", "Signatrue Length", base.DEC)
fcsignature = ProtoField.bytes("fcbm.fclist.signature", "Signature", base.SPACE)

ski = ProtoField.bytes("fcbm.ski", "Subject Key Identity", base.SPACE)
signature = ProtoField.bytes("fcbm.signature", "Signature", base.SPACE)

-- (1) register fields
fcbm_proto.fields = {
    fcbm_version, msg_type, length, ipversion, node_type, action,
    fc_num, srcip_num, dstip_num, siglen, local_asn, version, subversion,
    srcip_prefix, srcip_prefixlen, dstip_prefix, dstip_prefixlen,
    pasn, casn, nasn, fcski, algo_id, flags,
    fcsiglen, fcsignature, ski, signature
}

function fcbm_get_msg_type_name(msg_type_code)
    local msg_type_name = "Unknown"
    if msg_type_code == 1 then msg_type_name = "Certificate Information"
    elseif msg_type_code == 2 then msg_type_name = "Bingding Message BGP To FCServer"
    elseif msg_type_code == 3 then msg_type_name = "Bingding Message Broadcast"
    end
    return msg_type_name
end

function fcbm_get_ipversion_type_name(ipversion_code)
    local ipverion_name = "Unknown"
    if ipversion_code == 4 then ipverion_name = "IPv4"
    elseif ipversion_code == 6 then ipverion_name = "IPv6"
    end
    return ipverion_name
end

function fcbm_proto.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end

    -- set the name of protocol column
    pinfo.cols.protocol = fcbm_proto.name

    local curlen = 0
    local fieldlen = 0

    -- create a sub tree representing the synology finder protocol data
    local subtree = tree:add(fcbm_proto, buffer(), "Forwarding Commitment - Binding Message Protocol")
    -- (2) add fields
    subtree:add(fcbm_version, buffer(0, 1))

    msg_type_code = buffer(1, 1):int()
    subtree:add(msg_type, buffer(1, 1)):append_text(" (" .. fcbm_get_msg_type_name(msg_type_code) .. ")")

    subtree:add(length, buffer(2, 2))

    local ipversion_code = buffer(4, 1):int()
    subtree:add(ipversion, buffer(4, 1)):append_text(" (" .. fcbm_get_ipversion_type_name(ipversion_code) .. ")")

    subtree:add(node_type, buffer(5, 1))
    subtree:add(action, buffer(6, 1))
    subtree:add(fc_num, buffer(7, 1))
    subtree:add(srcip_num, buffer(8, 1))
    subtree:add(dstip_num, buffer(9, 1))
    subtree:add(siglen, buffer(10, 2))
    subtree:add(local_asn, buffer(12, 4))
    subtree:add(version, buffer(16, 4))
    subtree:add(subversion, buffer(20, 4))

    curlen = 24

    local srcPrefixTrees = subtree:add(fcbm_proto, buffer(), "Source Prefix List")
    for i=1, buffer(8, 1):int() do
        local srcPrefixTree = nil
        if ipversion_code == 4 then
            srcPrefixTree = srcPrefixTrees:add(fcbm_proto, buffer(curlen, 5),
            "" .. buffer(curlen, 4) .. "/" .. buffer(curlen+4, 1))
            srcPrefixTree:add(srcip_prefix, buffer(curlen, 4))
            curlen = curlen + 4
        elseif ipversion_code == 6 then
            srcPrefixTree = srcPrefixTrees:add(fcbm_proto, buffer(curlen, 17),
            "" .. buffer(curlen, 16) .. "/" .. buffer(curlen+16, 1))
            srcPrefixTree:add(srcip_prefix, buffer(curlen, 16))
            curlen = curlen + 16
        end
        srcPrefixTree:add(srcip_prefixlen, buffer(curlen, 1))
        curlen = curlen + 1
    end

    local dstPrefixTrees = subtree:add(fcbm_proto, buffer(), "Destination Prefix List")
    for i=1, buffer(9, 1):int() do
        local dstPrefixTree = nil
        if ipversion_code == 4 then
            dstPrefixTree = dstPrefixTrees:add(fcbm_proto, buffer(curlen, 5),
            "" .. buffer(curlen, 4) .. "/" .. buffer(curlen+4, 1))
            dstPrefixTree:add(dstip_prefix, buffer(curlen, 4))
            curlen = curlen + 4
        elseif ipversion_code == 6 then
            dstPrefixTree = dstPrefixTrees:add(fcbm_proto, buffer(curlen, 17),
            "" .. buffer(curlen, 16) .. "/" .. buffer(curlen+16, 1))
            dstPrefixTree:add(dstip_prefix, buffer(curlen, 16))
            curlen = curlen + 16
        end
        dstPrefixTree:add(dstip_prefixlen, buffer(curlen, 1))
        curlen = curlen + 1
    end

    local fclistsTree = subtree:add(fcbm_proto, buffer(), "FC List")
    for i=1, buffer(7, 1):int() do
        local fclistTree = fclistsTree:add(fcbm_proto, buffer(curlen, 36 + buffer(curlen+34, 2):int()),
        "FC (" .. buffer(curlen, 4):int() .. ", " .. buffer(curlen+4, 4):int()
        .. ", " .. buffer(curlen+8, 4):int() .. ")")
        fclistTree:add(pasn, buffer(curlen, 4))
        curlen = curlen + 4
        fclistTree:add(casn, buffer(curlen, 4))
        curlen = curlen + 4
        fclistTree:add(nasn, buffer(curlen, 4))
        curlen = curlen + 4
        fclistTree:add(fcski, buffer(curlen, 20))
        curlen = curlen + 20
        fclistTree:add(algo_id, buffer(curlen, 1))
        curlen = curlen + 1
        fclistTree:add(flags, buffer(curlen, 1))
        curlen = curlen + 1
        fclistTree:add(fcsiglen, buffer(curlen, 2))
        curlen = curlen + 2
        fieldlen = buffer(curlen-2, 2):int()
        fclistTree:add(fcsignature, buffer(curlen, fieldlen))
        curlen = curlen + fieldlen
    end

    local sigTree = subtree:add(fcbm_proto, buffer(curlen, buffer:len()-curlen), "Signature Block")
    if buffer(10, 2):int() > 0 then
        sigTree:add(ski, buffer(curlen, 20))
        curlen  = curlen + 20

        fieldlen = buffer(10, 2):int()
        sigTree:add(signature, buffer(curlen, fieldlen))
        curlen  = curlen + fieldlen
    end

end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(23160, fcbm_proto)

