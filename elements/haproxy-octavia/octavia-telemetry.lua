-- SPDX-License-Identifier: Apache-2.0
-- Loaded into the shared Lua state once per traced listener.
local listener_id, collector_socket, service_name, span_name = ...
local arguments = { select(5, ...) }
assert(listener_id and listener_id:match("^[a-f0-9-]+$"),
       "telemetry requires a listener UUID")
assert(collector_socket and collector_socket:match("^/[A-Za-z0-9_./-]+$"),
       "telemetry requires a private filesystem UNIX socket")
assert(service_name and #service_name <= 253 and service_name:match("^[A-Za-z0-9_.:/-]+$"),
       "invalid telemetry service name")
assert(span_name and #span_name <= 256 and span_name:match("^[A-Za-z0-9_.:/ -]+$")
       and not span_name:match("^ ") and not span_name:match(" $")
       and not span_name:find("  ", 1, true), "invalid telemetry span name")

local function unhex(encoded)
    assert(#encoded % 2 == 0, "invalid telemetry data encoding")
    return (encoded:gsub("..", function(pair) return string.char(tonumber(pair, 16)) end))
end

local function load_export_headers(config)
    local fields = {}
    for item in config:gmatch("[^,]+") do
        local name, value = item:match("^([0-9a-f]+):([0-9a-f]+)$")
        assert(name and value, "invalid telemetry export field encoding")
        fields[#fields + 1] = unhex(name) .. ": " .. unhex(value) .. "\r\n"
    end
    return table.concat(fields)
end

local function load_attributes(config)
    local result = {}
    for item in config:gmatch("[^,]+") do
        local source, name, value = item:match("^(%a+):([0-9a-f]+):([0-9a-f]+)$")
        assert(source == "Literal" or source == "Header" or source == "Attribute",
               "invalid telemetry attribute source")
        result[#result + 1] = { source = source, name = unhex(name), value = unhex(value) }
    end
    return result
end

local export_headers
local export_prefix = "export_headers="
if arguments[1] and arguments[1]:sub(1, #export_prefix) == export_prefix then
    export_headers = load_export_headers(
        table.remove(arguments, 1):sub(#export_prefix + 1))
end
local attributes
local config_prefix = "attributes="
if arguments[1] and arguments[1]:sub(1, #config_prefix) == config_prefix then
    attributes = load_attributes(table.remove(arguments, 1):sub(#config_prefix + 1))
end
local base_n, base_d, parent_n, parent_d = table.unpack(arguments)

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

-- The original scripts may also load into this Lua state. The attribute
-- actions use their own registry so registration order cannot change behavior.
local action_prefix = attributes and "octavia-trace-attributes" or "octavia-trace"
local namespace = attributes and "octavia_telemetry_attributes" or "octavia_telemetry"
if export_headers then
    action_prefix = action_prefix .. "-export-headers"
    namespace = namespace .. "_export_headers"
end
local exporters_key = namespace .. "_exporters"
local entropy_key = namespace .. "_entropy"
local exporters = _G[exporters_key] or {}
local entropy = _G[entropy_key]
local pending = core.queue()
assert(not exporters[listener_id], "duplicate telemetry listener")
exporters[listener_id] = {
    service_name = service_name,
    span_name = span_name,
    pending = pending,
    base_rate = base_rate,
    parent_rate = parent_rate,
    attributes = attributes,
}
local queue_limit = 128
local var_name = "txn." .. namespace

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
    return trace_id, parent_id, tonumber(flags, 16)
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
        local bytes = entropy:read(4)
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

local status_key = "http.response.status_code"
local known_methods = {}
if attributes then
    local methods = os.getenv("OTEL_INSTRUMENTATION_HTTP_KNOWN_METHODS")
                    or "CONNECT,DELETE,GET,HEAD,OPTIONS,PATCH,POST,PUT,QUERY,TRACE"
    for method in methods:gmatch("[^,]+") do
        known_methods[method] = true
    end
end
local request_attributes = {
    ["http.request.method"] = function(txn)
        local method = txn.f:method()
        return known_methods[method] and method or "_OTHER"
    end,
    ["url.path"] = function(txn) return txn.f:path() end,
    -- HAProxy returns a Boolean sample as the Lua integer 0 or 1.
    ["url.scheme"] = function(txn) return txn.f:ssl_fc() == 1 and "https" or "http" end,
}

local function capture_request_attributes(txn, configured)
    local values = {}
    for index, attribute in ipairs(configured) do
        if attribute.source == "Header" then
            -- Full field line, including any commas. HAProxy matches case insensitively.
            values[index] = txn.f:req_fhdr(attribute.value, 1)
        elseif attribute.source == "Attribute" then
            local fetch = request_attributes[attribute.value]
            if fetch then
                values[index] = fetch(txn)
            end
        end
    end
    return values
end

local function start_span(txn, id)
    local exporter = exporters[id]
    if not exporter then
        return
    end
    local trace_id, parent_id, parent_flags = read_parent(txn)
    local random = entropy:read(24)
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
        sampled = parent_flags & 1 == 1 and sample(exporter.parent_rate)
    else
        sampled = sample(exporter.base_rate)
    end
    local trace_flags = (parent_flags or 2) & 2
    if sampled then
        trace_flags = trace_flags | 1
    end
    txn:set_priv({
        exporter = exporter,
        trace_id = trace_id,
        span_id = span_id,
        parent_id = parent_id,
        sampled = sampled,
        trace_flags = trace_flags,
        start_ns = sampled and unix_nanos(),
        request_attributes = sampled and exporter.attributes
                             and capture_request_attributes(txn, exporter.attributes),
    })
    txn:set_var(var_name, true)
end

local function propagate_span(txn)
    if not txn:get_var(var_name) then
        return
    end
    local span = txn:get_priv()
    txn.http:req_set_header(
        "traceparent", ("00-%s-%s-%02x"):format(span.trace_id, span.span_id, span.trace_flags))
    if not span.parent_id then
        txn.http:req_del_header("tracestate")
    end
end

-- OTLP/HTTP JSON uses hex IDs, numeric enum values and decimal strings for
-- 64-bit fields. Dynamic attribute strings are JSON-escaped separately.
local otlp = [[{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"%s"}}]},
"scopeSpans":[{"scope":{"name":"octavia.amphora"},"spans":[{"traceId":"%s","spanId":"%s"%s,
"name":"%s","kind":2,"flags":%d,"startTimeUnixNano":"%d","endTimeUnixNano":"%d",
"attributes":[%s]%s}]}]}]}]]

local function json_escape(value)
    return (value:gsub('[%z\1-\31\\"]', function(byte)
        if byte == '\\' or byte == '"' then
            return '\\' .. byte
        end
        return ('\\u%04x'):format(byte:byte())
    end))
end

local function integer_attribute(name, value)
    return ('{"key":"%s","value":{"intValue":"%d"}}'):format(name, value)
end

local function span_attributes(txn, span, http_status)
    local standard = integer_attribute(status_key, http_status)
    local configured = span.exporter.attributes
    if not configured then
        return standard
    end
    local encoded = { standard }
    for index, attribute in ipairs(configured) do
        local source, name, key = attribute.source, attribute.name, attribute.value
        if name ~= status_key then
            if source == "Attribute" and key == status_key then
                encoded[#encoded + 1] = integer_attribute(name, http_status)
            else
                local value = span.request_attributes[index]
                if source == "Literal" then
                    value = key
                elseif source == "Header" and value == nil then
                    value = txn.f:res_fhdr(key, 1)
                end
                if value ~= nil and utf8.len(value) then
                    encoded[#encoded + 1] =
                        ('{"key":"%s","value":{"stringValue":"%s"}}'):format(name, json_escape(value))
                end
            end
        end
    end
    return table.concat(encoded, ",")
end

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
    -- Preserve W3C flags and add the OTLP bits marking a known remote parent.
    local flags = span.trace_flags | (span.parent_id and 0x300 or 0)
    local status = http_status >= 500 and ',"status":{"code":2}' or ""
    exporter.pending:push(otlp:format(
        exporter.service_name, span.trace_id, span.span_id, parent,
        exporter.span_name, flags, span.start_ns, unix_nanos(),
        span_attributes(txn, span, http_status), status))
end

if not _G[exporters_key] then
    -- Open the descriptor during configuration, before privileges drop.
    entropy = assert(io.open("/dev/urandom", "rb"))
    _G[entropy_key] = entropy
    _G[exporters_key] = exporters
    core.register_action(action_prefix .. "-start", { "http-req" }, start_span, 1)
    core.register_action(action_prefix .. "-propagate", { "http-req" }, propagate_span)
    core.register_action(action_prefix .. "-finish", { "http-after-res" }, finish_span)
end

-- Each listener has its own bounded export task and queue.
-- Only the private listener's configured backend selects the destination.
local function export(body)
    local client = core.tcp()
    client:settimeout(1)
    if client:connect(collector_socket) then
        local request = ("POST /v1/traces HTTP/1.1\r\nHost: otlp.internal\r\n" ..
                         "Content-Type: application/json\r\nContent-Length: %d\r\n" ..
                         "Connection: close\r\n%s\r\n%s"):format(
                             #body, export_headers or "", body)
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
