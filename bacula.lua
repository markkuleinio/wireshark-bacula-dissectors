
bacula_protocol = Proto("Bacula", "Bacula Network Backup Protocol")
local DIR_PROTOCOL_NAME = "Bacula-Director"
local FD_PROTOCOL_NAME = "Bacula-File"
local SD_PROTOCOL_NAME = "Bacula-Storage"

p_len = ProtoField.uint32("bacula.len", "Length", base.DEC)
p_data = ProtoField.string("bacula.data", "Data", base.ASCII)
p_is_dir = ProtoField.bool("bacula.director", "Bacula Director")
p_is_fd = ProtoField.bool("bacula.file", "Bacula File Daemon")
p_is_sd = ProtoField.bool("bacula.storage", "Bacula Storage Daemon")

bacula_protocol.fields = { p_len, p_data, p_is_dir, p_is_fd, p_is_sd }

local default_settings =
{
    dir_port = "9101",
    fd_port = "9102",
    sd_port = "9103",
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


function bacula_protocol.dissector(buffer, pktinfo, tree)
    local pktlength = buffer:len()
    if pktlength == 0 then
        return 0
    end
    local subtree = tree:add(bacula_protocol, buffer(), "Bacula Protocol")
    -- set Protocol column manually to get it in mixed case instead of all caps
    if tostring(pktinfo.src_port) == default_settings.dir_port or tostring(pktinfo.dst_port) == default_settings.dir_port then
        pktinfo.cols.protocol = DIR_PROTOCOL_NAME
        subtree:add(p_is_dir, true, "This is Bacula Director"):set_generated()
    elseif tostring(pktinfo.src_port) == default_settings.fd_port or tostring(pktinfo.dst_port) == default_settings.fd_port then
        pktinfo.cols.protocol = FD_PROTOCOL_NAME
        subtree:add(p_is_fd, true, "This is Bacula File Daemon"):set_generated()
    elseif tostring(pktinfo.src_port) == default_settings.sd_port or tostring(pktinfo.dst_port) == default_settings.sd_port then
        pktinfo.cols.protocol = SD_PROTOCOL_NAME
        subtree:add(p_is_sd, true, "This is Bacula Storage Daemon"):set_generated()
    else
        pktinfo.cols.protocol = "Bacula"
        subtree:add("Could not identify Bacula component based on ports"):set_generated()
    end
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
        if offset+block_len > pktlength then
            -- Not enough data in this TCP packet, need more
            pktinfo.desegment_offset = 0
            pktinfo.desegment_len = block_len - pktlength
            return
        end
        local bsocktree = subtree:add(bacula_protocol, buffer(offset, block_len),
            "BSOCK packet #" .. num .. ", " .. block_len .. " bytes")
        if length > 0 then
            if bit.band(length, 0x60000000) > 0 then
                bsocktree:add(p_len, buffer(offset, 4), actual_length)
                if compressed then
                    bsocktree:add(buffer(offset, 4), "BNET_COMPRESSED")
                    bsocktree:add(buffer(offset+4, actual_length), "Compressed data")
                end
                if bit.band(length, 0x20000000) > 0 then
                    bsocktree:add(buffer(offset, 4), "BNET_HDR_EXTEND")
                    bsocktree:add(p_data, buffer(offset+4, actual_length))
                end
            else
                bsocktree:add(p_len, buffer(offset, 4))
                bsocktree:add(p_data, buffer(offset+4, actual_length))
            end
        else
            bsocktree:add(buffer(offset, 4), "Signal code: ", signal_code)
        end
        offset = offset + block_len
        num = num + 1
    end
end


-- #####################################################


function bacula_protocol.init()
    -- Clear the tables
    dir_timestamps = {}
    fd_timestamps = {}
end


local function enableDissector()
    ports = default_settings.dir_port .. "," .. default_settings.fd_port .. "," .. default_settings.sd_port
    DissectorTable.get("tcp.port"):add(ports, bacula_protocol)
end
-- Call it now, because we're enabled by default
enableDissector()

local function disableDissector()
    ports = default_settings.dir_port .. "," .. default_settings.fd_port .. "," .. default_settings.sd_port
    DissectorTable.get("tcp.port"):remove(ports, bacula_protocol)
end

-- Register the preferences
-- Need to rearrange everything, maybe by using subdissectors
bacula_protocol.prefs.reassemble = Pref.bool("Reassemble Bacula messages spanning multiple TCP segments",
    default_settings.reassemble, "Whether the Bacula dissector should reassemble messages " ..
    "spanning multiple TCP segments. To use this option, you must also enable \"Allow subdissectors to " ..
    "reassemble TCP streams\" in the TCP protocol settings")

bacula_protocol.prefs.info_text = Pref.bool("Show Bacula protocol data in Info column",
    default_settings.info_text, "Disable this to show the default TCP protocol data in the Info column")

bacula_protocol.prefs.ports_in_info = Pref.bool("Show TCP ports in Info column",
    default_settings.ports_in_info, "Disable this to have only Bacula data in the Info column")

bacula_protocol.prefs.dir_port = Pref.range("Director port", default_settings.dir_port,
    "Set the TCP port for Bacula Director, default is " .. default_settings.dir_port, 65535)
bacula_protocol.prefs.fd_port = Pref.range("File Daemon port", default_settings.fd_port,
    "Set the TCP port for Bacula File Daemon, default is " .. default_settings.fd_port, 65535)
bacula_protocol.prefs.sd_port = Pref.range("Storage Daemon port", default_settings.sd_port,
    "Set the TCP port for Bacula Storage Daemon, default is " .. default_settings.sd_port, 65535)

bacula_protocol.prefs.text = Pref.statictext("This dissector is written in Lua.","")


-- the function for handling preferences being changed
function bacula_protocol.prefs_changed()
    if default_settings.reassemble ~= bacula_protocol.prefs.reassemble then
        default_settings.reassemble = bacula_protocol.prefs.reassemble
        -- capture file reload needed
        reload()
    elseif default_settings.info_text ~= bacula_protocol.prefs.info_text then
        default_settings.info_text = bacula_protocol.prefs.info_text
        -- capture file reload needed
        reload()
    elseif default_settings.ports_in_info ~= bacula_protocol.prefs.ports_in_info then
        default_settings.ports_in_info = bacula_protocol.prefs.ports_in_info
        -- capture file reload needed
        reload()
    elseif default_settings.dir_port ~= bacula_protocol.prefs.dir_port or
           default_settings.fd_port ~= bacula_protocol.prefs.fd_port or
           default_settings.sd_port ~= bacula_protocol.prefs.sd_port
    then
        disableDissector()
        default_settings.dir_port = bacula_protocol.prefs.dir_port
        default_settings.fd_port = bacula_protocol.prefs.fd_port
        default_settings.sd_port = bacula_protocol.prefs.sd_port
        enableDissector()
    end
end
