
bacula_director_protocol = Proto("Bacula-Dir", "Bacula Director Protocol")
bacula_file_daemon_protocol = Proto("Bacula-FD", "Bacula File Daemon Protocol")
local DIR_PROTOCOL_NAME = "Bacula-Dir"
local FD_PROTOCOL_NAME = "Bacula-FD"

p_fd_len = ProtoField.uint32("bacula-fd.len", "Length", base.DEC)
p_fd_data = ProtoField.string("bacula-fd.data", "Data", base.ASCII)

bacula_file_daemon_protocol.fields = { p_fd_len, p_fd_data }

local default_settings =
{
    dir_ports = "9101",   -- the default TCP ports
    fd_ports = "9102",
    sd_ports = "9103",
    reassemble = true,    -- whether we try reassembly or not
    info_text = true,     -- show our own Info column data or TCP defaults
    ports_in_info = true, -- show TCP ports in Info column
}

-- tables for data saved about the sessions
local dir_timestamps = {}
local fd_timestamps = {}

local BNET_COMPRESSED = 0x40000000
local BNET_HDR_EXTEND = 0x20000000

local function band(a, b)
    if bit.band(a, b) > 0 then return true
    else return false
    end
end


-- #######################################
-- protocol dissector functions
-- #######################################


function bacula_director_protocol.dissector(buffer, pktinfo, tree)
    local pktlength = buffer:len()
    if pktlength == 0 then
        return 0
    end
    -- set Protocol column manually to get it in mixed case instead of all caps
    pktinfo.cols.protocol = DIR_PROTOCOL_NAME

    local offset = 0
    local len_code = 0
    while offset < pktlength
    do
        len_code = buffer(offset,4):le_int()
        local subtree = tree:add(bacula_director_protocol, buffer(), "Bacula Director Protocol")
        subtree:add(len_code)
        break
    end
end


function bacula_file_daemon_protocol.dissector(buffer, pktinfo, tree)
    local pktlength = buffer:len()
    if pktlength == 0 then
        return 0
    end
    -- set Protocol column manually to get it in mixed case instead of all caps
    pktinfo.cols.protocol = FD_PROTOCOL_NAME
    local subtree = tree:add(bacula_file_daemon_protocol, buffer(), "Bacula File Daemon Protocol")
    local offset = 0
    local num = 1
    local length, actual_length, block_len
    local signal_code
    local compressed, hdr_extend
    while offset < pktlength
    do
        length = buffer(offset, 4):int()
        if length > 0 then
            actual_length = bit.band(length, 0x1FFFFFFF)
            compressed = bit.band(length, BNET_COMPRESSED) > 0
            hdr_extend = bit.band(length, BNET_HDR_EXTEND) > 0
            block_len = actual_length + 4
        else
            signal_code = length
            block_len = 4
        end
        local bsocktree = subtree:add(bacula_file_daemon_protocol, buffer(offset, block_len),
            "BSOCK packet #" .. num .. ", " .. block_len .. " bytes")
        if length > 0 then
            if bit.band(length, 0x60000000) > 0 then
                bsocktree:add(p_fd_len, buffer(offset, 4), actual_length)
                if compressed then
                    bsocktree:add(buffer(offset, 4), "BNET_COMPRESSED")
                    bsocktree:add(buffer(offset+4, actual_length), "Compressed data")
                end
                if bit.band(length, 0x20000000) > 0 then
                    bsocktree:add(buffer(offset, 4), "BNET_HDR_EXTEND")
                    bsocktree:add(p_fd_data, buffer(offset+4, actual_length))
                end
            else
                bsocktree:add(p_fd_len, buffer(offset, 4))
                bsocktree:add(p_fd_data, buffer(offset+4, actual_length))
            end
        else
            bsocktree:add(buffer(offset, 4), "Signal code: ", signal_code)
        end
        offset = offset + block_len
        num = num + 1
    end
end


-- #####################################################


function bacula_director_protocol.init()
    -- Clear the tables
    dir_timestamps = {}
end


function bacula_file_daemon_protocol.init()
    -- Clear the tables
    fd_timestamps = {}
end


local function enableDissector()
    DissectorTable.get("tcp.port"):add(default_settings.dir_ports, bacula_director_protocol)
    DissectorTable.get("tcp.port"):add(default_settings.fd_ports, bacula_file_daemon_protocol)
end
-- Call it now, because we're enabled by default
enableDissector()

local function disableDissector()
    DissectorTable.get("tcp.port"):remove(default_settings.dir_ports, bacula_director_protocol)
    DissectorTable.get("tcp.port"):remove(default_settings.fd_ports, bacula_file_daemon_protocol)
end

-- Register the preferences
-- Need to rearrange everything, maybe by using subdissectors
bacula_director_protocol.prefs.reassemble = Pref.bool("Reassemble Bacula messages spanning multiple TCP segments",
    default_settings.reassemble, "Whether the Bacula dissector should reassemble messages " ..
    "spanning multiple TCP segments. To use this option, you must also enable \"Allow subdissectors to " ..
    "reassemble TCP streams\" in the TCP protocol settings")

bacula_director_protocol.prefs.info_text = Pref.bool("Show Bacula protocol data in Info column",
    default_settings.info_text, "Disable this to show the default TCP protocol data in the Info column")

bacula_director_protocol.prefs.ports_in_info = Pref.bool("Show TCP ports in Info column",
    default_settings.ports_in_info, "Disable this to have only Bacula data in the Info column")

bacula_director_protocol.prefs.dir_ports = Pref.range("Port(s)", default_settings.dir_ports,
    "Set the TCP port(s) for Bacula Director, default is " .. default_settings.dir_ports, 65535)

bacula_director_protocol.prefs.fd_ports = Pref.range("Port(s)", default_settings.fd_ports,
    "Set the TCP port(s) for Bacula File Daemon, default is " .. default_settings.fd_ports, 65535)

bacula_director_protocol.prefs.text = Pref.statictext("This dissector is written in Lua.","")


-- the function for handling preferences being changed
function bacula_director_protocol.prefs_changed()
    if default_settings.reassemble ~= bacula_director_protocol.prefs.reassemble then
        default_settings.reassemble = bacula_director_protocol.prefs.reassemble
        -- capture file reload needed
        reload()
    elseif default_settings.info_text ~= bacula_director_protocol.prefs.info_text then
        default_settings.info_text = bacula_director_protocol.prefs.info_text
        -- capture file reload needed
        reload()
    elseif default_settings.ports_in_info ~= bacula_director_protocol.prefs.ports_in_info then
        default_settings.ports_in_info = bacula_director_protocol.prefs.ports_in_info
        -- capture file reload needed
        reload()
    elseif default_settings.dir_ports ~= bacula_director_protocol.prefs.dir_ports or
           default_settings.fd_ports ~= bacula_director_protocol.prefs.fd_ports
    then
        disableDissector()
        default_settings.dir_ports = bacula_director_protocol.prefs.dir_ports
        enableDissector()
    end
end
