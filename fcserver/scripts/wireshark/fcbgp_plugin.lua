-- @author      basilguo@163.com
-- @version     0.1.0
-- @description Parse Forwarding Commitment
--                  - Binding Message
--                  - Router Topology
-- @usage       Adding this script to the lua script's directory.
--      Following this steps: "Help->About->Folders->Personal Lua Plugins"
--
--
-- create a Proto object
local fc_proto = Proto("fcbgp", "FC-BGP (Forwarding Commitment-based BGP) Protocol")

-- create ProtoField Objects
-- general header
fc_version = ProtoField.int8("fcbgp.version", "Protocol Version", base.DEC)
fc_msg_type = ProtoField.int8("fcbgp.msg_type", "Message Type", base.DEC)
fc_msg_length = ProtoField.int16("fcbgp.msg_length", "Message Length", base.DEC)

-- bm packet format
fcbm_bmversion = ProtoField.int8("fcbgp.bm.bmversion", "Binding Message Version", base.DEC)
fcbm_ipversion = ProtoField.int8("fcbgp.bm.ipversion", "IP Version", base.DEC)
fcbm_flags = ProtoField.int8("fcbgp.bm.flags", "Flags", base.DEC)
fcbm_algoid = ProtoField.int8("fcbgp.bm.algoid", "Algorithm ID", base.DEC)
fcbm_srcip_num = ProtoField.int8("fcbgp.bm.srcip_num", "Number of Source Prefixes", base.DEC)
fcbm_dstip_num = ProtoField.int8("fcbgp.bm.dstip_num", "Number of Destination Prefixes", base.DEC)
fcbm_fc_num = ProtoField.int8("fcbgp.bm.fc_num", "Number of FCs", base.DEC)
fcbm_siglen = ProtoField.int16("fcbgp.bm.siglen", "Signature Length", base.DEC)
fcbm_local_asn = ProtoField.int32("fcbgp.bm.local_asn", "Local AS Number", base.DEC)
fcbm_version = ProtoField.int32("fcbgp.bm.version", "Binding Message Version", base.DEC)
fcbm_subversion = ProtoField.int32("fcbgp.bm.subversion", "Binding Message SubVersion", base.DEC)
fcbm_srcip_prefix = ProtoField.bytes("fcbgp.bm.srcip.prefix", "Source Prefix", base.SPACE)
fcbm_srcip_prefixlen = ProtoField.int8("fcbgp.bm.srcip.prefixlen", "Source Prefix Length", base.DEC)
fcbm_dstip_prefix = ProtoField.bytes("fcbgp.bm.dstip.prefix", "Destination Prefix", base.SPACE)
fcbm_dstip_prefixlen = ProtoField.int8("fcbgp.bm.dstip.prefixlen", "Destination Prefix Length", base.DEC)
fcbm_fclist_pasn = ProtoField.int32("fcbgp.bm.fclist.pasn", "Previous ASN", base.DEC)
fcbm_fclist_casn = ProtoField.int32("fcbgp.bm.fclist.casn", "Current ASN", base.DEC)
fcbm_fclist_nasn = ProtoField.int32("fcbgp.bm.fclist.nasn", "Nexthop ASN", base.DEC)
fcbm_fclist_ski = ProtoField.bytes("fcbgp.bm.fclist.ski", "Subject Key Identifier", base.SPACE)
fcbm_fclist_algo_id = ProtoField.int8("fcbgp.bm.fclist.algo_id", "Algorithm Identity", base.DEC)
fcbm_fclist_flags = ProtoField.int8("fcbgp.bm.fclist.flags", "Flags", base.DEC)
fcbm_fclist_fcsiglen = ProtoField.int16("fcbgp.bm.fclist.siglen", "Signatrue Length", base.DEC)
fcbm_fclist_signature = ProtoField.bytes("fcbgp.bm.fclist.signature", "Signature", base.SPACE)
fcbm_ski = ProtoField.bytes("fcbgp.bm.ski", "Subject Key Identifier", base.SPACE)
fcbm_signature = ProtoField.bytes("fcbgp.bm.signature", "Signature", base.SPACE)

-- topo packet format
topo_action = ProtoField.int8("fcbgp.topo.action", "Action", base.DEC)
topo_reserved = ProtoField.bytes("fcbgp.topo.reserved", "Reserved", base.SPACE)
topo_bgpid = ProtoField.bytes("fcbgp.topo.bgpid", "BGP ID", base.SPACE)
topo_local_asn = ProtoField.int32("fcbgp.topo.local_asn", "Local AS Number", base.DEC)
topo_neighbor_num = ProtoField.int32("fcbgp.topo.neighbor_num", "Number of Neighbors", base.DEC)
topo_neighbors = ProtoField.bytes("fcbgp.topo.neighbors", "Neighbor", base.SPACE)

-- register fields
fc_proto.fields = {fc_version, fc_msg_type, fc_msg_length, topo_action, topo_reserved, topo_bgpid, topo_local_asn,
                   topo_neighbor_num, topo_neighbors, fcbm_bmversion, fcbm_ipversion, fcbm_flags, fcbm_algoid,
                   fcbm_srcip_num, fcbm_dstip_num, fcbm_fc_num, fcbm_siglen, fcbm_local_asn, fcbm_version,
                   fcbm_subversion, fcbm_srcip_prefix, fcbm_srcip_prefixlen, fcbm_dstip_prefix, fcbm_dstip_prefixlen,
                   fcbm_fclist_pasn, fcbm_fclist_casn, fcbm_fclist_nasn, fcbm_fclist_ski, fcbm_fclist_algo_id,
                   fcbm_fclist_flags, fcbm_fclist_fcsiglen, fcbm_fclist_signature, fcbm_ski, fcbm_signature}
local function trim(s)
    return s:match("^%s*(.-)%s*$")
end

local function get_field_name(field)
    -- https://stackoverflow.com/questions/52012229/how-do-you-access-name-of-a-protofield-after-declaration
    -- First, convert the field into a string
    -- this is going to result in a long string with 
    -- a bunch of info we dont need

    local fieldString = tostring(field)
    -- fieldString looks like:
    -- ProtoField(188403): Foo  myproto.foo base.DEC 0000000000000000 00000000 (null) 

    -- Split the string on '.' characters
    a, b = fieldString:match "([^.]*).(.*)"
    -- Split the first half of the previous result (a) on ':' characters
    a, b = a:match "([^.]*):(.*)"

    -- At this point, b will equal " Foo myproto" 
    -- and we want to strip out that abreviation "abvr" part

    -- Count the number of times spaces occur in the string
    local spaceCount = select(2, string.gsub(b, " ", ""))

    -- Declare a counter
    local counter = 0

    -- Declare the name we are going to return
    local constructedName = ''

    -- Step though each word in (b) separated by spaces
    for word in b:gmatch("%w+") do
        -- If we hav reached the last space, go ahead and return 
        if counter == spaceCount - 1 then
            return trim(constructedName)
        end

        -- Add the current word to our name 
        constructedName = constructedName .. word .. " "

        -- Increment counter
        counter = counter + 1
    end
end

local function fc_proto_bm_bmversion(buffer, fcbgp_tree)
    local bmversion_buf = buffer(4, 1)
    fcbgp_tree:add(fcbm_bmversion, bmversion_buf)
end

local function fc_proto_bm_ipversion(buffer, fcbgp_tree)
    local ipversion_buf = buffer(5, 1)
    local ipversion_code = ipversion_buf:int()
    local ipversion_str = " (Unknown)"
    if ipversion_code == 4 then
        ipversion_str = " (IPv4)"
    elseif ipversion_code == 6 then
        ipversion_str = " (IPv6)"
    end
    fcbgp_tree:add(fcbm_ipversion, ipversion_buf):append_text(ipversion_str)
end

local function fc_proto_bm_bmflags(buffer, fcbgp_tree)
    local bmflags_buf = buffer(6, 1)
    local bmflags_code = bmflags_buf:int()
    local bmflags_str = "Unknown"
    if bmflags_code == 0x00 then
        bmflags_str = " (Onpath Node, Update)"
    elseif bmflags_code == 0x80 then
        bmflags_str = " (Offpath Node, Update)"
    elseif bmflags_code == 0x40 then
        bmflags_str = " (Onpath Node, Withdraw)"
    elseif bmflags_code == 0xC0 then
        bmflags_str = " (Offpath Node, Withdraw)"
    end
    fcbgp_tree:add(fcbm_flags, bmflags_buf):append_text(bmflags_str)
end

local function fc_proto_bm_src_prefix(buffer, fcbgp_tree)
    local ipversion_code = buffer(5, 1):int()
    local ip_prefix_len = 6 * ipversion_code - 20
    local fcbm_srcip_num_code = buffer(10, 2):int()
    local srcip_buffer = buffer(curlen, fcbm_srcip_num_code * (1 + ip_prefix_len))
    local srcPrefixTrees = fcbgp_tree:add(fc_proto, srcip_buffer, "Destination Prefix List")
    local src_prefix_tree_buf = nil
    local src_prefix_tree_str = nil
    local fcbm_srcip_prefix_buf = nil
    local fcbm_srcip_prefix_code = nil
    local fcbm_srcip_prefix_str = nil
    local fcbm_srcip_prefixlen_buf = nil
    local fcbm_srcip_prefixlen_code = nil
    local fcbm_srcip_prefixlen_str = nil
    local srcPrefixTree = nil
    for i = 1, fcbm_srcip_num_code do
        if ipversion_code == 4 then
            fcbm_srcip_prefix_buf = buffer(curlen, 4)
            fcbm_srcip_prefix_code = fcbm_srcip_prefix_buf:int()
            fcbm_srcip_prefix_str = fcbm_srcip_prefix_buf:ipv4()

            fcbm_srcip_prefixlen_buf = buffer(curlen + 4, 1)
            fcbm_srcip_prefixlen_code = fcbm_srcip_prefixlen_buf:uint()
            fcbm_srcip_prefixlen_str = string.format("%s: %d", get_field_name(fcbm_srcip_prefixlen),
                fcbm_srcip_prefixlen_code)

            src_prefix_tree_str = string.format("%s/%d", fcbm_srcip_prefix_str, fcbm_srcip_prefixlen_code)
            src_prefix_tree_buf = buffer(curlen, 5)

            srcPrefixTree = srcPrefixTrees:add(fc_proto, src_prefix_tree_buf, src_prefix_tree_str)
            fcbm_srcip_prefix_str = string.format("%s: %s", get_field_name(fcbm_srcip_prefix), fcbm_srcip_prefix_str)
            srcPrefixTree:add(fcbm_srcip_prefix, fcbm_srcip_prefix_buf):set_text(fcbm_srcip_prefix_str)
            srcPrefixTree:add(fcbm_srcip_prefixlen, fcbm_srcip_prefixlen_buf):set_text(fcbm_srcip_prefixlen_str)

            curlen = curlen + 5
        elseif ipversion_code == 6 then
            fcbm_srcip_prefix_buf = buffer(curlen, 16)
            fcbm_srcip_prefix_str = fcbm_srcip_prefix_buf:ipv6()

            fcbm_srcip_prefixlen_buf = buffer(curlen + 16, 1)
            fcbm_srcip_prefixlen_code = fcbm_srcip_prefixlen_buf:uint()
            fcbm_srcip_prefixlen_str = string.format("%s: %d", get_field_name(fcbm_srcip_prefixlen),
                fcbm_srcip_prefixlen_code)

            src_prefix_tree_str = string.format("%s/%d", fcbm_srcip_prefix_str, fcbm_srcip_prefixlen_code)
            src_prefix_tree_buf = buffer(curlen, 17)

            srcPrefixTree = srcPrefixTrees:add(fc_proto, src_prefix_tree_buf, src_prefix_tree_str)
            fcbm_srcip_prefix_str = string.format("%s: %s", get_field_name(fcbm_srcip_prefix), fcbm_srcip_prefix_str)
            srcPrefixTree:add(fcbm_srcip_prefix, fcbm_srcip_prefix_buf):set_text(fcbm_srcip_prefix_str)
            srcPrefixTree:add(fcbm_srcip_prefixlen, fcbm_srcip_prefixlen_buf):set_text(fcbm_srcip_prefixlen_str)

            curlen = curlen + 17
        end
    end
end

local function fc_proto_bm_dst_prefix(buffer, fcbgp_tree)
    local ipversion_code = buffer(5, 1):int()
    local ip_prefix_len = 6 * ipversion_code - 20
    local fcbm_dstip_num_code = buffer(10, 2):int()
    local dstip_buffer = buffer(curlen, fcbm_dstip_num_code * (1 + ip_prefix_len))
    local dstPrefixTrees = fcbgp_tree:add(fc_proto, dstip_buffer, "Destination Prefix List")
    local dst_prefix_tree_buf = nil
    local dst_prefix_tree_str = nil
    local fcbm_dstip_prefix_buf = nil
    local fcbm_dstip_prefix_code = nil
    local fcbm_dstip_prefix_str = nil
    local fcbm_dstip_prefixlen_buf = nil
    local fcbm_dstip_prefixlen_code = nil
    local fcbm_dstip_prefixlen_str = nil
    local dstPrefixTree = nil
    for i = 1, fcbm_dstip_num_code do
        if ipversion_code == 4 then
            fcbm_dstip_prefix_buf = buffer(curlen, 4)
            fcbm_dstip_prefix_code = fcbm_dstip_prefix_buf:int()
            fcbm_dstip_prefix_str = fcbm_dstip_prefix_buf:ipv4()

            fcbm_dstip_prefixlen_buf = buffer(curlen + 4, 1)
            fcbm_dstip_prefixlen_code = fcbm_dstip_prefixlen_buf:uint()
            fcbm_dstip_prefixlen_str = string.format("%s: %d", get_field_name(fcbm_dstip_prefixlen),
                fcbm_dstip_prefixlen_code)

            dst_prefix_tree_str = string.format("%s/%d", fcbm_dstip_prefix_str, fcbm_dstip_prefixlen_code)
            dst_prefix_tree_buf = buffer(curlen, 5)

            dstPrefixTree = dstPrefixTrees:add(fc_proto, dst_prefix_tree_buf, dst_prefix_tree_str)
            fcbm_dstip_prefix_str = string.format("%s: %s", get_field_name(fcbm_dstip_prefix), fcbm_dstip_prefix_str)
            dstPrefixTree:add(fcbm_dstip_prefix, fcbm_dstip_prefix_buf):set_text(fcbm_dstip_prefix_str)
            dstPrefixTree:add(fcbm_dstip_prefixlen, fcbm_dstip_prefixlen_buf):set_text(fcbm_dstip_prefixlen_str)

            curlen = curlen + 5
        elseif ipversion_code == 6 then
            fcbm_dstip_prefix_buf = buffer(curlen, 16)
            fcbm_dstip_prefix_str = fcbm_dstip_prefix_buf:ipv6()

            fcbm_dstip_prefixlen_buf = buffer(curlen + 16, 1)
            fcbm_dstip_prefixlen_code = fcbm_dstip_prefixlen_buf:uint()
            fcbm_dstip_prefixlen_str = string.format("%s: %d", get_field_name(fcbm_dstip_prefixlen),
                fcbm_dstip_prefixlen_code)

            dst_prefix_tree_str = string.format("%s/%d", fcbm_dstip_prefix_str, fcbm_dstip_prefixlen_code)
            dst_prefix_tree_buf = buffer(curlen, 17)

            dstPrefixTree = dstPrefixTrees:add(fc_proto, dst_prefix_tree_buf, dst_prefix_tree_str)
            fcbm_dstip_prefix_str = string.format("%s: %s", get_field_name(fcbm_dstip_prefix), fcbm_dstip_prefix_str)
            dstPrefixTree:add(fcbm_dstip_prefix, fcbm_dstip_prefix_buf):set_text(fcbm_dstip_prefix_str)
            dstPrefixTree:add(fcbm_dstip_prefixlen, fcbm_dstip_prefixlen_buf):set_text(fcbm_dstip_prefixlen_str)

            curlen = curlen + 17
        end
    end
end

local function fc_proto_bm_fclist(buffer, fcbgp_tree)
    local fcbm_fc_num_code = buffer(12, 2):int()
    local fclistsTree = fcbgp_tree:add(fc_proto, buffer(curlen), "FC List")
    for i = 1, fcbm_fc_num_code do
        local pasn_buf = buffer(curlen, 4)
        local pasn_code = pasn_buf:int()
        local casn_buf = buffer(curlen + 4, 4)
        local casn_code = casn_buf:int()
        local nasn_buf = buffer(curlen + 8, 4)
        local nasn_code = nasn_buf:int()
        local total_fclist_length = 36 + buffer(curlen + 34, 2):int()
        local fclist_tree_str = string.format("FC(%d, %d, %d)", pasn_code, casn_code, nasn_code)
        local fclistTree = fclistsTree:add(fc_proto, buffer(curlen, total_fclist_length), fclist_tree_str)
        fclistTree:add(fcbm_fclist_pasn, pasn_buf)
        fclistTree:add(fcbm_fclist_casn, casn_buf)
        fclistTree:add(fcbm_fclist_nasn, nasn_buf)
        curlen = curlen + 12
        fclistTree:add(fcbm_fclist_ski, buffer(curlen, 20))
        curlen = curlen + 20
        fclistTree:add(fcbm_fclist_algo_id, buffer(curlen, 1))
        curlen = curlen + 1
        fclistTree:add(fcbm_fclist_flags, buffer(curlen, 1))
        curlen = curlen + 1
        local fcbm_fclist_fcsiglen_buf = buffer(curlen, 2)
        local fcbm_fclist_fcsiglen_code = fcbm_fclist_fcsiglen_buf:int()
        fclistTree:add(fcbm_fclist_fcsiglen, fcbm_fclist_fcsiglen_buf)
        curlen = curlen + 2
        fclistTree:add(fcbm_fclist_signature, buffer(curlen, fcbm_fclist_fcsiglen_code))
        curlen = curlen + fcbm_fclist_fcsiglen_code
    end

end

local function fc_proto_bm_signature(buffer, fcbgp_tree)
    local sigTree = fcbgp_tree:add(fc_proto, buffer(curlen, buffer:len() - curlen), "Signature Block")
    if buffer(14, 2):int() > 0 then
        sigTree:add(fcbm_ski, buffer(curlen, 20))
        curlen = curlen + 20
        fieldlen = buffer(14, 2):int()
        sigTree:add(fcbm_signature, buffer(curlen, fieldlen))
        curlen = curlen + fieldlen
    end
end

function fc_proto_bm_handler(buffer, fcbgp_tree, ipversion_code, ip_prefix_len)
    local fieldlen = 0

    fc_proto_bm_bmversion(buffer, fcbgp_tree)
    fc_proto_bm_ipversion(buffer, fcbgp_tree)
    fc_proto_bm_bmflags(buffer, fcbgp_tree)

    fcbgp_tree:add(fcbm_algoid, buffer(7, 1))
    fcbgp_tree:add(fcbm_srcip_num, buffer(8, 2))
    fcbgp_tree:add(fcbm_dstip_num, buffer(10, 2))
    fcbgp_tree:add(fcbm_fc_num, buffer(12, 2))
    fcbgp_tree:add(fcbm_siglen, buffer(14, 2))
    fcbgp_tree:add(fcbm_local_asn, buffer(16, 4))
    fcbgp_tree:add(fcbm_version, buffer(20, 4))
    fcbgp_tree:add(fcbm_subversion, buffer(24, 4))

    curlen = 28
    fc_proto_bm_src_prefix(buffer, fcbgp_tree)
    fc_proto_bm_dst_prefix(buffer, fcbgp_tree)
    fc_proto_bm_fclist(buffer, fcbgp_tree)
    fc_proto_bm_signature(buffer, fcbgp_tree)
end

local function fc_proto_topo_action(buffer, fcbgp_tree)
    local topo_action_buf = buffer(4, 1)
    local topo_action_code = topo_action_buf:int()
    local topo_action_str = " (Unknown)"
    if topo_action_code == 0 then
        topo_action_str = " (Add)"
    elseif topo_action_code == 1 then
        topo_action_str = " (Delete)"
    end
    fcbgp_tree:add(topo_action, topo_action_buf):append_text(topo_action_str)
end

local function fc_proto_topo_reserved(buffer, fcbgp_tree)
    local topo_reserved_buf = buffer(5, 3)
    local topo_reserved_code = topo_reserved_buf:int()
    local topo_reserved_name = get_field_name(topo_reserved)
    local topo_reserved_str = string.format("%s: %d", topo_reserved_name, topo_reserved_code)
    fcbgp_tree:add(topo_reserved, topo_reserved_buf):set_text(topo_reserved_str)
end

local function fc_proto_topo_bgpid(buffer, fcbgp_tree)
    local topo_bgpid_buf = buffer(8, 4)
    local topo_bgpid_str = string.format("%s: %s", get_field_name(topo_bgpid), topo_bgpid_buf:ipv4())
    fcbgp_tree:add(topo_bgpid, topo_bgpid_buf):set_text(topo_bgpid_str)
end

local function fc_proto_topo_local_asn(buffer, fcbgp_tree)
    fcbgp_tree:add(topo_local_asn, buffer(12, 4))
end

local function fc_proto_topo_neighbor_num(buffer, fcbgp_tree)
    topo_neighbor_num_code = buffer(16, 4):int()
    fcbgp_tree:add(topo_neighbor_num, buffer(16, 4))
end

local function fc_proto_topo_neighbors(buffer, fcbgp_tree)
    local curlen = 20
    local lower_limits = curlen
    local upper_limits = 4 * topo_neighbor_num_code
    neighbors_buffer = buffer(lower_limits, upper_limits)
    local topoNeighborTree = fcbgp_tree:add(fc_proto, neighbors_buffer, "Neighbors")
    for i = 1, topo_neighbor_num_code do
        local asn_code = buffer(curlen, 4):int()
        local asn_str = string.format("%s: %d", get_field_name(topo_neighbors), asn_code)
        topoNeighborTree:add(topo_neighbors, buffer(curlen, 4)):set_text(asn_str)
        curlen = curlen + 4
    end
end

function fc_proto_topo_handler(buffer, fcbgp_tree)
    fc_proto_topo_action(buffer, fcbgp_tree)
    fc_proto_topo_reserved(buffer, fcbgp_tree)
    fc_proto_topo_bgpid(buffer, fcbgp_tree)
    fc_proto_topo_local_asn(buffer, fcbgp_tree)
    fc_proto_topo_neighbor_num(buffer, fcbgp_tree)
    fc_proto_topo_neighbors(buffer, fcbgp_tree)
end

function fc_proto.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then
        return
    end

    -- set the name of protocol column
    pinfo.cols.protocol = fc_proto.name

    -- create a sub tree representing the synology finder protocol data
    local fcbgp_tree = tree:add(fc_proto, buffer(), "Forwarding Commitment Protocol")

    -- fc version
    fcbgp_tree:add(fc_version, buffer(0, 1))

    -- msg type, msg length, and continue decaping
    local msg_type_code = buffer(1, 1):int()
    if msg_type_code == 1 then
        msg_type_name = " (Certificate Information)"
        fcbgp_tree:add(fc_msg_type, buffer(1, 1)):append_text(msg_type_name)
        fcbgp_tree:add(fc_msg_length, buffer(2, 2))
    elseif msg_type_code == 2 then
        msg_type_name = " (Bingding Message - From BGP To FCServer Information)"
        fcbgp_tree:add(fc_msg_type, buffer(1, 1)):append_text(msg_type_name)
        fcbgp_tree:add(fc_msg_length, buffer(2, 2))
        fc_proto_bm_handler(buffer, fcbgp_tree)
    elseif msg_type_code == 3 then
        msg_type_name = " (Bingding Message - FCServer Broadcast Information)"
        fcbgp_tree:add(fc_msg_type, buffer(1, 1)):append_text(msg_type_name)
        fcbgp_tree:add(fc_msg_length, buffer(2, 2))
        fc_proto_bm_handler(buffer, fcbgp_tree)
    elseif msg_type_code == 4 then
        msg_type_name = " (Topology Link Information)"
        fcbgp_tree:add(fc_msg_type, buffer(1, 1)):append_text(msg_type_name)
        fcbgp_tree:add(fc_msg_length, buffer(2, 2))
        fc_proto_topo_handler(buffer, fcbgp_tree)
    end
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(23162, fc_proto)
