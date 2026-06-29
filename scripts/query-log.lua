-- Optimized query logger for PowerDNS Recursor
-- FIX: persistent file handle, batch flush, no os.execute fork
-- Original opened/closed file 60x/sec + forked shell for rotation
-- This version: persistent fd, flush every 50 writes, atomic rotate

local log_fd = nil
local write_buf = {}
local BUF_SIZE = 50
local MAX_LINES = 200000
local line_count = 0

local qtype_map = {
    [1]="A",[28]="AAAA",[5]="CNAME",[15]="MX",
    [16]="TXT",[2]="NS",[6]="SOA",[12]="PTR",
    [33]="SRV",[255]="ANY",[257]="CAA",
}

local function get_fd()
    if not log_fd then
        log_fd = io.open("/var/log/pdns-query.log", "a")
    end
    return log_fd
end

function preresolve(dq)
    local qt = tonumber(dq.qtype)
    local qts = qtype_map[qt] or tostring(qt)
    local line = os.date("%Y-%m-%d %H:%M:%S") .. "|"
                 .. tostring(dq.remoteaddr) .. "|"
                 .. tostring(dq.qname) .. "|" .. qts

    write_buf[#write_buf + 1] = line
    line_count = line_count + 1

    -- Batch flush every BUF_SIZE writes
    if #write_buf >= BUF_SIZE then
        local fd = get_fd()
        if fd then
            fd:write(table.concat(write_buf, "\n") .. "\n")
            fd:flush()
        end
        write_buf = {}
    end

    -- Atomic rotate when file too large (no shell fork)
    if line_count >= MAX_LINES then
        if log_fd then
            log_fd:close()
            log_fd = nil
        end
        os.rename("/var/log/pdns-query.log", "/var/log/pdns-query.log.1")
        line_count = 0
        write_buf = {}
    end

    return false
end
