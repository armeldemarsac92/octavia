-- SPDX-License-Identifier: Apache-2.0

-- Production uses the fixed adapter socket. A trusted lua-load argument lets
-- local tests use a private socket without changing the action's interface.
local socket_path = ... or "/run/octavia/grpc-authz.sock"
assert(socket_path:match("^/[A-Za-z0-9_./-]+$"), "invalid authorization socket path")
local destination = "unix@" .. socket_path
local content_type = "application/x-www-form-urlencoded"
local body_content_type = "application/vnd.octavia.grpc-authz-body"
local max_form = 256 * 1024
local max_forward_body = 2147483647
local body_send_chunk_size = 64 * 1024
local max_reply_headers = 1024
-- The applet streams the body, but its response headers must fit in one HTX
-- buffer. Octavia keeps at least the default 16 KiB minus 1 KiB for data.
local max_denial_headers = 15 * 1024 - 256
-- HAProxy copies samples through a buffer-sized scratch area on reads.
local decision_chunk_size = 8 * 1024
local deadline_ms = 3000

local allowed_var = "txn.octavia_grpc_auth_allowed"
local denied_var = "txn.octavia_grpc_auth_denied"
local decision_count_var = "txn.octavia_grpc_auth_decision_chunks"
local decision_chunk_var = "txn.octavia_grpc_auth_decision_"
local response_applied_var = "txn.octavia_grpc_auth_response_applied"

local protected = {
    ["connection"] = true, ["content-length"] = true, ["host"] = true,
    ["keep-alive"] = true, ["proxy-connection"] = true, ["te"] = true,
    ["trailer"] = true, ["transfer-encoding"] = true, ["upgrade"] = true,
}

local function header_name(name)
    return name:match("^[!#$%%&'*+.^_`|~A-Za-z0-9%-]+$") ~= nil
end

local function mutable(name)
    -- HTX stores a header name's length in eight bits.
    return #name <= 255 and header_name(name) and name == name:lower() and not protected[name]
end

local function encode(value)
    return (value:gsub("[^A-Za-z0-9_.~-]", function(byte)
        return string.format("%%%02X", byte:byte())
    end))
end

local function decode(value)
    local unescaped = value:gsub("%%[0-9a-fA-F][0-9a-fA-F]", "")
    if unescaped:find("%", 1, true) then
        return nil
    end
    return (value:gsub("%+", " "):gsub("%%(%x%x)", function(hex)
        return string.char(tonumber(hex, 16))
    end))
end

local function selected_headers(encoded)
    if encoded == "-" then
        return nil, true
    end
    if #encoded % 2 ~= 0 or not encoded:match("^[0-9a-f]+$") then
        return nil, false
    end
    local list = encoded:gsub("..", function(hex)
        return string.char(tonumber(hex, 16))
    end)
    local selected = {}
    for name in (list .. ","):gmatch("(.-),") do
        if (not header_name(name) and name ~= ":authority") or name ~= name:lower() then
            return nil, false
        end
        selected[name] = true
    end
    return selected, true
end

local function request_form(txn, allowlist)
    local selected, valid = selected_headers(allowlist)
    if not valid then
        return nil
    end
    local headers = txn.http:req_get_headers()
    local method = txn.sf:method()
    local uri = txn.f:url()
    local version = txn.sf:req_ver()
    if not method or not uri or not version or version == "" then
        return nil
    end

    -- HTX presents a normalized absolute target for HTTP/2 with :authority.
    -- For origin-form HTTP/1.x the scheme comes from the real connection.
    local scheme, host, path = uri:match("^([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]+)(.*)$")
    if not scheme then
        local tls = txn.f:ssl_fc()
        scheme = (tls == 1 or tls == true) and "https" or "http"
        host = method == "CONNECT" and uri or (headers.host and headers.host[0] or "")
        path = uri
    elseif path == "" then
        path = method == "OPTIONS" and "*" or "/"
    elseif path:sub(1, 1) == "?" then
        path = "/" .. path
    end
    local protocol = "HTTP/" .. (version:gsub("^([23])%.0$", "%1"))
    local parts = {}
    local size = 0
    local function add(key, value)
        local field = encode(key) .. "=" .. encode(value)
        size = size + #field + 1
        if size > max_form + 1 then
            return false
        end
        parts[#parts + 1] = field
        return true
    end

    if not add("method", method) or not add("path", path) or not add("host", host)
       or not add("scheme", scheme:lower()) or not add("protocol", protocol) then
        return nil
    end
    -- HTX has folded the HTTP/2 authority into the request target and Host.
    -- A filtered Envoy header map must preserve the requested field name.
    if protocol == "HTTP/2" and host ~= "" and (not selected or selected[":authority"])
       and not add("h.:authority", host) then
        return nil
    end
    for name, values in pairs(headers) do
        if not selected or selected[name] then
            for index = 0, #values do
                if not add("h." .. name, values[index]) then
                    return nil
                end
            end
        end
    end
    return table.concat(parts, "&")
end

local function valid_query(query)
    return not query:find("[%z\1-\32\127#]")
end

local function parse_decision(body)
    local result = { request = {}, response = {} }
    local first = true
    for field in (body .. "&"):gmatch("(.-)&") do
        local raw_key, raw_value = field:match("^([^=]+)=(.*)$")
        local key = raw_key and decode(raw_key)
        local value = raw_value and decode(raw_value)
        if not key or not value then
            return nil
        end
        if first then
            if key ~= "decision" or (value ~= "allow" and value ~= "deny") then
                return nil
            end
            result.allowed = value == "allow"
            first = false
        elseif key == "status" and not result.allowed then
            local status = value:match("^[2-5][0-9][0-9]$") and tonumber(value)
            if result.status or not status then
                return nil
            end
            result.status = status
        elseif key == "body" and not result.allowed then
            if result.body ~= nil then
                return nil
            end
            result.body = value
        elseif key == "query" and result.allowed then
            if result.query ~= nil or not valid_query(value) then
                return nil
            end
            result.query = value
        elseif key == "remove" and result.allowed and mutable(value) then
            result.request[#result.request + 1] = { kind = "remove", name = value }
        else
            local ops = result.request
            if result.allowed and key:sub(1, 9) == "response." then
                ops = result.response
                key = key:sub(10)
            end
            local kind, name = key:match("^([a-z]+)%.(.+)$")
            if not name or not mutable(name) or value:find("[%z\1-\8\10-\31\127]")
               or (kind ~= "add" and kind ~= "set" and kind ~= "ifabsent" and kind ~= "ifpresent") then
                return nil
            end
            ops[#ops + 1] = { kind = kind, name = name, value = value }
        end
    end
    if not result.allowed then
        result.status = result.status or 403
        result.body = result.body or ""
        if #result.body > 0 and (result.status == 204 or result.status == 205 or result.status == 304) then
            return nil
        end
    end
    return result
end

-- Simulate the ordered operations to preserve duplicate values and to treat
-- presence as the state after each operation, also for a local denial.
local function update_headers(headers, operations, delete, add)
    local changed = {}
    for _, op in ipairs(operations) do
        local existing = headers[op.name]
        if op.kind == "remove" then
            if delete then
                delete(op.name)
            end
            headers[op.name] = nil
            changed[op.name] = true
        elseif (op.kind ~= "ifabsent" or not existing) and (op.kind ~= "ifpresent" or existing) then
            if op.kind == "set" or op.kind == "ifpresent" then
                if delete then
                    delete(op.name)
                end
                existing = nil
            end
            if add then
                add(op.name, op.value)
            end
            if existing then
                existing[#existing + 1] = op.value
            else
                headers[op.name] = { [0] = op.value }
            end
            changed[op.name] = true
        end
    end
    return changed
end

local function mutations_applied(expected, actual, changed)
    -- HAProxy 3.0's Lua add_header has no return value even on HTX overflow.
    for name in pairs(changed) do
        local wanted, found = expected[name], actual[name]
        if (wanted == nil) ~= (found == nil) then
            return false
        end
        if wanted then
            if #wanted ~= #found then
                return false
            end
            for index = 0, #wanted do
                if wanted[index] ~= found[index] then
                    return false
                end
            end
        end
    end
    return true
end

local function denial_headers(result)
    local headers = {}
    update_headers(headers, result.request)
    local size = 0
    for name, values in pairs(headers) do
        for index = 0, #values do
            size = size + #name + #values[index] + 8 -- HTX block overhead
        end
    end
    return size <= max_denial_headers and headers or nil
end

local function store_decision(txn, raw)
    local index = 0
    for first = 1, #raw, decision_chunk_size do
        index = index + 1
        if not txn:set_var(decision_chunk_var .. index,
                           raw:sub(first, first + decision_chunk_size - 1)) then
            return false
        end
    end
    return txn:set_var(decision_count_var, index)
end

local function take_decision(txn)
    local count = txn:get_var(decision_count_var)
    if not count then
        return nil, false
    end
    txn:unset_var(decision_count_var)
    local parts = {}
    for index = 1, count do
        local name = decision_chunk_var .. index
        parts[index] = txn:get_var(name)
        txn:unset_var(name)
    end
    for index = 1, count do
        if not parts[index] then
            return nil, true
        end
    end
    return table.concat(parts), true
end

local function post_form(path, form)
    local client = core.httpclient()
    -- The adapter bounds its entire exchange and output. The client timeout
    -- also handles an adapter that has stopped responding.
    local response = client:post{
        url = "http://localhost" .. path,
        dst = destination,
        timeout = deadline_ms,
        headers = {
            ["connection"] = { "close" },
            ["content-type"] = { content_type },
        },
        body = form,
    }
    if not response or response.status ~= 200 or not response.body or #response.body > max_form then
        return nil
    end
    local length = response.headers["content-length"]
    local kind = response.headers["content-type"]
    if not length or length[1] or not length[0]:match("^[0-9]+$")
       or tonumber(length[0]) ~= #response.body or not kind or kind[1] or kind[0] ~= content_type then
        return nil
    end
    return response.body
end

local function now_ms()
    local time = core.now()
    return time.sec * 1000 + time.usec / 1000
end

local function exchange_body(socket, request, body)
    local deadline = now_ms() + deadline_ms
    local function has_time()
        local remaining = deadline - now_ms()
        if remaining <= 0 then
            return false
        end
        socket:settimeout(remaining / 1000)
        return true
    end

    if not has_time() or not socket:connect(destination) or not has_time()
       or socket:send(request) ~= #request then
        return nil
    end
    -- Sending slices keeps HAProxy's Socket.send copy bounded regardless of
    -- the request size. The metadata and payload share no Lua string.
    for first = 1, #body, body_send_chunk_size do
        local last = math.min(first + body_send_chunk_size - 1, #body)
        if not has_time() or socket:send(body, first, last) ~= last - first + 1 then
            return nil
        end
    end
    if not has_time() then
        return nil
    end
    -- The adapter closes each HTTP/1.0 exchange. A numeric read bounds the
    -- response even if the adapter returns a malformed or oversized reply.
    local reply = socket:receive(max_reply_headers + max_form + 1)
    if now_ms() < deadline then
        return reply
    end
end

local function post_body(path, form, body)
    local request = string.format("POST %s HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n"
        .. "Content-Type: %s\r\nOctavia-Form-Length: %d\r\nContent-Length: %d\r\n\r\n%s",
        path, body_content_type, #form, #form + #body, form)
    local socket = core.tcp()
    local ok, reply = pcall(exchange_body, socket, request, body)
    socket:close()
    if not ok or not reply or #reply > max_reply_headers + max_form then
        return nil
    end

    local head, body_start = reply:match("^HTTP/1%.0 200 [^\r\n]*\r\n(.-)\r\n\r\n()")
    if not head or body_start - 1 > max_reply_headers then
        return nil
    end
    local length, kind
    for line in (head .. "\r\n"):gmatch("(.-)\r\n") do
        local name, value = line:match("^([^:]+):[ \t]*(.-)[ \t]*$")
        if not name or not header_name(name) then
            return nil
        end
        name = name:lower()
        if name == "content-length" and not length and value:match("^[0-9]+$") then
            length = tonumber(value)
        elseif name == "content-type" and not kind then
            kind = value
        elseif name == "content-length" or name == "content-type" or name == "transfer-encoding" then
            return nil
        end
    end
    if not length or length > max_form or length ~= #reply - body_start + 1 or kind ~= content_type then
        return nil
    end
    return reply:sub(body_start)
end

local function get_decision(txn, pool, allowlist, body_limit)
    if not pool:match("^[0-9a-f]+%-[0-9a-f]+%-[0-9a-f]+%-[0-9a-f]+%-[0-9a-f]+$")
       or #pool ~= 36 or pool:sub(9, 9) ~= "-" or pool:sub(14, 14) ~= "-"
       or pool:sub(19, 19) ~= "-" or pool:sub(24, 24) ~= "-" then
        return nil
    end
    local form = request_form(txn, allowlist)
    if not form then
        return nil
    end
    local path = "/v1/check/" .. pool
    local raw
    if body_limit then
        local limit = body_limit:match("^[0-9]+$") and tonumber(body_limit)
        if not limit or limit <= 0 or limit > max_forward_body then
            return nil
        end
        local body = txn.f:octavia_auth_body()
        if body == nil or #body > limit then
            return nil
        end
        raw = post_body(path, form, body)
    else
        raw = post_form(path, form)
    end
    if raw then
        return parse_decision(raw), raw
    end
end

local function authorize(txn, pool, allowlist, body_limit)
    txn:unset_var(allowed_var)
    txn:unset_var(denied_var)
    take_decision(txn)
    txn:unset_var(response_applied_var)

    -- HAProxy's rule immediately after this action returns 503 if Lua fails
    -- before publishing success. Keep Lua/transport errors out of the logs.
    local ok, result, raw = pcall(get_decision, txn, pool, allowlist, body_limit)
    if not ok or not result then
        return
    end
    if not result.allowed then
        if denial_headers(result) and store_decision(txn, raw) then
            txn:set_var(denied_var, true)
        end
        return
    end

    if #result.request ~= 0 then
        local http = txn.http
        local expected = http:req_get_headers()
        local changed = update_headers(expected, result.request,
            function(name) http:req_del_header(name) end,
            function(name, value) http:req_add_header(name, value) end)
        if not mutations_applied(expected, http:req_get_headers(), changed) then
            return
        end
    end
    if result.query ~= nil then
        if result.query == "" then
            local uri = txn.f:url():match("^[^?]*")
            local scheme = uri:match("^([A-Za-z][A-Za-z0-9+.-]*)://")
            scheme = scheme and scheme:lower()
            if txn.f:fc_http_major() >= 2 and (scheme == "http" or scheme == "https") then
                -- set_uri clears HTX's normalized-URI flag. Use the path so
                -- an HTTP/1 origin still sees an origin-form request target.
                uri = txn.f:path() or uri
            end
            if not txn.http:req_set_uri(uri) then
                return
            end
        elseif not txn.http:req_set_query(result.query) then
            return
        end
    end
    if #result.response ~= 0 and not store_decision(txn, raw) then
        return
    end
    txn:set_var(allowed_var, true)
end

local function authorize_response(txn)
    local raw, had_decision = take_decision(txn)
    if had_decision then
        local result = raw and parse_decision(raw)
        if not result or not result.allowed then
            return
        end
        local http = txn.http
        local expected = http:res_get_headers()
        local changed = update_headers(expected, result.response,
            function(name) http:res_del_header(name) end,
            function(name, value) http:res_add_header(name, value) end)
        if not mutations_applied(expected, http:res_get_headers(), changed) then
            return
        end
    end
    txn:set_var(response_applied_var, true)
end

local function deny(applet)
    local raw = take_decision(applet)
    local result = raw and parse_decision(raw)
    local headers = result and not result.allowed and denial_headers(result)
    if not headers then
        applet:set_status(503)
        applet:add_header("content-length", "0")
        applet:start_response()
        return
    end
    applet:set_status(result.status)
    for name, values in pairs(headers) do
        for index = 0, #values do
            applet:add_header(name, values[index])
        end
    end
    if result.status ~= 204 and result.status ~= 304 then
        applet:add_header("content-length", tostring(#result.body))
    end
    applet:start_response()
    if #result.body ~= 0 and applet.method ~= "HEAD" then
        applet:send(result.body)
    end
end

core.register_action("octavia-grpc-auth", { "http-req" }, authorize, 2)
core.register_action("octavia-grpc-auth-body", { "http-req" }, authorize, 3)
core.register_action("octavia-grpc-auth-response", { "http-res", "http-after-res" }, authorize_response)
core.register_service("octavia-grpc-auth-denial", "http", deny)
