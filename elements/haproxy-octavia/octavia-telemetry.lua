-- SPDX-License-Identifier: Apache-2.0
-- Loaded into the shared Lua state once per traced listener.
local listener_id, collector_socket, service_name, span_name, base_n, base_d, parent_n, parent_d = ...
assert(listener_id and listener_id:match("^[a-f0-9-]+$"),
       "telemetry requires a listener UUID")
assert(collector_socket and collector_socket:match("^/[A-Za-z0-9_./-]+$"),
       "telemetry requires a private filesystem UNIX socket")
assert(service_name and #service_name <= 253 and service_name:match("^[A-Za-z0-9_.:/-]+$"),
       "invalid telemetry service name")
assert(span_name and #span_name <= 256 and span_name:match("^[A-Za-z0-9_.:/ -]+$")
       and not span_name:match("^ ") and not span_name:match(" $")
       and not span_name:find("  ", 1, true), "invalid telemetry span name")

local function fraction(numerator, denominator)
    if numerator == nil and denominator == nil then
        return nil
    end
    assert(numerator and denominator and numerator:match("^%d+$")
           and denominator:match("^%d+$"), "invalid telemetry sampling rate")
    local n, d = tonumber(numerator), tonumber(denominator)
    assert(d >= 1 and d <= 2147483647 and n <= d, "invalid telemetry sampling rate")
    return { numerator = n, denominator = d }
end

local base_rate = fraction(base_n, base_d)
local parent_rate = fraction(parent_n, parent_d)
assert(base_rate or not parent_rate, "telemetry sampling requires a base rate")

local exporters = octavia_telemetry_exporters or {}
local pending = core.queue()
assert(not exporters[listener_id], "duplicate telemetry listener")
exporters[listener_id] = {
    service_name = service_name,
    span_name = span_name,
    pending = pending,
    base_rate = base_rate,
    parent_rate = parent_rate,
}
local queue_limit = 128
local var_name = "txn.octavia_telemetry"

local function hex(bytes)
    return (bytes:gsub(".", function(byte) return ("%02x"):format(byte:byte()) end))
end

local traceparent_prefix = "^([a-f0-9][a-f0-9])%-([a-f0-9]+)%-([a-f0-9]+)%-([a-f0-9][a-f0-9])"

local function read_parent(txn)
    if txn.f:req_fhdr_cnt("traceparent") ~= 1 then
        return
    end
    local header = txn.sf:req_fhdr("traceparent")
    if #header < 55 then
        return
    end
    local version, trace_id, parent_id, flags = header:match(traceparent_prefix)
    if not version or version == "ff" or #trace_id ~= 32 or #parent_id ~= 16
       or trace_id == ("0"):rep(32) or parent_id == ("0"):rep(16)
       or (#header > 55 and (version == "00" or header:sub(56, 56) ~= "-")) then
        return
    end
    return trace_id, parent_id, tonumber(flags, 16) & 1 == 1
end

local function sample(rate)
    if not rate or rate.numerator == rate.denominator then
        return true
    end
    if rate.numerator == 0 then
        return false
    end
    -- Discard the incomplete last bucket for an unbiased integer draw.
    local range = 1 << 32
    local limit = range - range % rate.denominator
    while true do
        local bytes = octavia_telemetry_entropy:read(4)
        if not bytes then
            return false
        end
        local draw = string.unpack(">I4", bytes)
        if draw < limit then
            return draw % rate.denominator < rate.numerator
        end
    end
end

local function unix_nanos()
    local time = core.now()
    return time.sec * 1000000000 + time.usec * 1000
end

local function start_span(txn, id)
    local exporter = exporters[id]
    if not exporter then
        return
    end
    local trace_id, parent_id, parent_sampled = read_parent(txn)
    local random = octavia_telemetry_entropy:read(24)
    if not random then
        return
    end
    local span_id = hex(random:sub(17))
    trace_id = trace_id or hex(random:sub(1, 16))
    if span_id == ("0"):rep(16) or trace_id == ("0"):rep(32) then
        return
    end
    local sampled
    if parent_id and exporter.parent_rate then
        sampled = parent_sampled and sample(exporter.parent_rate)
    else
        sampled = sample(exporter.base_rate)
    end
    txn:set_priv({
        exporter = exporter,
        trace_id = trace_id,
        span_id = span_id,
        parent_id = parent_id,
        sampled = sampled,
        start_ns = sampled and unix_nanos(),
    })
    txn:set_var(var_name, true)
end

local function propagate_span(txn)
    if not txn:get_var(var_name) then
        return
    end
    local span = txn:get_priv()
    local flags = span.sampled and "01" or "00"
    txn.http:req_set_header(
        "traceparent", ("00-%s-%s-%s"):format(span.trace_id, span.span_id, flags))
    if not span.parent_id then
        txn.http:req_del_header("tracestate")
    end
end

-- OTLP/HTTP JSON uses hex IDs, numeric enum values and decimal strings for
-- 64-bit fields. All interpolated strings are restricted to safe alphabets.
local otlp = [[{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"%s"}}]},
"scopeSpans":[{"scope":{"name":"octavia.amphora"},"spans":[{"traceId":"%s","spanId":"%s"%s,
"name":"%s","kind":2,"flags":%d,"startTimeUnixNano":"%d","endTimeUnixNano":"%d",
"attributes":[{"key":"http.response.status_code","value":{"intValue":"%d"}}]%s}]}]}]}]]

local function finish_span(txn)
    if not txn:get_var(var_name) then
        return
    end
    local span = txn:get_priv()
    txn:set_priv(nil)
    txn:unset_var(var_name)
    if not span.sampled then
        return
    end
    local http_status = txn.f:status()
    local exporter = span.exporter
    if not http_status or exporter.pending:size() >= queue_limit then
        return
    end
    local parent = span.parent_id and (',"parentSpanId":"%s"'):format(span.parent_id) or ""
    -- The sampled bit plus both OTLP remote-parent bits for a W3C parent.
    local flags = span.parent_id and (0x300 | 1) or 1
    local status = http_status >= 500 and ',"status":{"code":2}' or ""
    exporter.pending:push(otlp:format(
        exporter.service_name, span.trace_id, span.span_id, parent,
        exporter.span_name, flags, span.start_ns, unix_nanos(),
        http_status, status))
end

if not octavia_telemetry_exporters then
    -- Open the descriptor during configuration, before privileges drop.
    octavia_telemetry_entropy = assert(io.open("/dev/urandom", "rb"))
    octavia_telemetry_exporters = exporters
    core.register_action("octavia-trace-start", { "http-req" }, start_span, 1)
    core.register_action("octavia-trace-propagate", { "http-req" }, propagate_span)
    core.register_action("octavia-trace-finish", { "http-after-res" }, finish_span)
end

-- Each listener has its own bounded export task and queue.
-- Only the private listener's configured backend selects the destination.
local function export(body)
    local client = core.tcp()
    client:settimeout(1)
    if client:connect(collector_socket) then
        local request = ("POST /v1/traces HTTP/1.1\r\nHost: otlp.internal\r\n" ..
                         "Content-Type: application/json\r\nContent-Length: %d\r\n" ..
                         "Connection: close\r\n\r\n%s"):format(#body, body)
        if client:send(request) then
            -- Wait for the status without buffering the collector's response.
            client:receive(12)
        end
    end
    client:close()
end

core.register_task(function()
    while true do
        local body = pending:pop_wait()
        if body then
            export(body)
        end
    end
end)
