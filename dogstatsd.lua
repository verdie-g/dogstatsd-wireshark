os.setlocale("C") -- to parse correctly floating numbers

dogstatsd_protocol = Proto("DogStatsD", "Datadog StatsD Protocol")

event_title = ProtoField.string("dogstatsd.event.title", "Title")
event_msg = ProtoField.string("dogstatsd.event.msg", "Message")
event_priority = ProtoField.string("dogstatsd.event.priority", "Priority")
event_alert_type = ProtoField.string("dogstatsd.event.alert_type", "Alert Type")

service_check_name = ProtoField.string("dogstatsd.service_check.name", "Name")
service_check_status = ProtoField.uint8("dogstatsd.service_check.status", "Status", base.DEC,
  { [0] = "ok", [1] = "warning", [2] = "critical", [3] = "unknown" })
service_check_msg = ProtoField.string("dogstatsd.service_check.msg", "Message")

metric_name = ProtoField.string("dogstatsd.metric.name", "Name")
metric_value = ProtoField.double("dogstatsd.metric.value", "Value")
metric_type = ProtoField.string("dogstatsd.metric.type", "Type")
metric_sampling = ProtoField.double("dogstatsd.metric.sampling", "Sampling")

time = ProtoField.absolute_time("dogstatsd.time", "Time", base.LOCAL)
hostname = ProtoField.string("dogstatsd.hostname", "Hostname")
tags = ProtoField.string("dogstatsd.tags", "Tags")

dogstatsd_protocol.fields = {
  event_title,
  event_msg,
  event_priority,
  event_alert_type,
  service_check_name,
  service_check_status,
  service_check_msg,
  metric_name,
  metric_value,
  metric_type,
  metric_sampling,
  time,
  hostname,
  tags
}

-- buf packet's buffer (https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html#lua_class_Tvb)
-- pinfo: packet information (https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Pinfo.html#lua_class_Pinfo)
-- tree: packet details view (https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html#lua_class_TreeItem)
function dogstatsd_protocol.dissector(buf, pinfo, tree)
  pinfo.cols.protocol = dogstatsd_protocol.name -- set protocol column

  local subtree = tree:add(dogstatsd_protocol, buf(), "DogStatsD Protocol Data")
  local idx = 0

  for msg in string.gmatch(buf:raw(), "[^\n]+") do
    local msg_buf = buf(idx, msg:len())
    if buf:raw(idx, 2) == "_e" then
      local event_tree = subtree:add(dogstatsd_protocol, msg_buf, "Event")
      dissect_event(msg_buf, event_tree)
    elseif buf:raw(idx, 3) == "_sc" then
      local service_check_tree = subtree:add(dogstatsd_protocol, msg_buf, "Service Check")
      dissect_service_check(msg_buf, service_check_tree)
    else
      local metric_tree = subtree:add(dogstatsd_protocol, msg_buf, "Metric")
      dissect_metric(msg_buf, metric_tree)
    end

    idx = idx + msg:len() + 1 -- + 1 for \n
  end
end

-- _e{<TITLE>.length,<TEXT>.length}:<TITLE>|<TEXT>|d:<TIMESTAMP>|h:<HOSTNAME>|p:<PRIORITY>|t:<ALERT_TYPE>|#<TAG_KEY_1>:<TAG_VALUE_1>,<TAG_2>
function dissect_event(buf, tree)
  local _, _, title_length_str, msg_length_str, title, msg = string.find(buf:string(), "^_e{(%d+),(%d+)}:([^|]+)|([^|]+)")
  local idx = 6 + title_length_str:len() + msg_length_str:len()
  tree:add(event_title, buf(idx, title:len()), title)
  idx = idx + title:len() + 1 -- +1 for |
  tree:add(event_msg, buf(idx, msg:len()), msg)
  idx = idx + msg:len()

  if idx >= buf:len() then return end

  for section in string.gmatch(buf(idx):string(), "[^|]+") do
    local section_buf = buf(idx + 1, section:len()) -- +1 for |
    local section_type = string.sub(section, 1, 1)
    if section_type == "d" then
      local nstime = timestamp_to_nstime(section_buf(2):string())
      tree:add(time, section_buf(2), nstime)
    elseif section_type == "h" then tree:add(hostname, section_buf(2), section_buf(2):string())
    elseif section_type == "p" then tree:add(event_priority, section_buf(2), section_buf(2):string())
    elseif section_type == "t" then tree:add(event_alert_type, section_buf(2), section_buf(2):string())
    elseif section_type == "#" then tree:add(tags, section_buf(1), section_buf(1):string())
    end

    idx = idx + 1 + section:len() -- +1 for |
  end
end

-- _sc|<NAME>|<STATUS>|d:<TIMESTAMP>|h:<HOSTNAME>|#<TAG_KEY_1>:<TAG_VALUE_1>,<TAG_2>|m:<SERVICE_CHECK_MESSAGE>
function dissect_service_check(buf, tree)
  local _, _, name, status = string.find(buf:string(), "^_sc|([^|]+)|(%d)")
  local idx = 4
  tree:add(service_check_name, buf(idx, name:len()), name)
  idx = idx + name:len() + 1 -- +1 for |
  tree:add(service_check_status, buf(idx, 1), status)
  idx = idx + 1 -- +1 for status length
  
  if idx >= buf:len() then return end

  for section in string.gmatch(buf(idx):string(), "[^|]+") do
    local section_buf = buf(idx + 1, section:len()) -- +1 for |
    local section_type = string.sub(section, 1, 1)
    if section_type == "d" then
      local nstime = timestamp_to_nstime(section_buf(2):string())
      tree:add(time, section_buf(2), nstime)
    elseif section_type == "h" then tree:add(hostname, section_buf(2), section_buf(2):string())
    elseif section_type == "#" then tree:add(tags, section_buf(1), section_buf(1):string())
    elseif section_type == "m" then tree:add(service_check_msg, section_buf(2), section_buf(2):string())
    end

    idx = idx + 1 + section:len() -- +1 for |
  end
end

-- <METRIC_NAME>:<VALUE>|<TYPE>|@<SAMPLE_RATE>|#<TAG_KEY_1>:<TAG_VALUE_1>,<TAG_2>
function dissect_metric(buf, tree)
  local _, _, name, value, type = string.find(buf:string(), "^([^:]+):([^|]+)|([^|]+)")
  local idx = 0
  tree:add(metric_name, buf(idx, name:len()), name)
  idx = idx + name:len() + 1 -- +1 for :
  tree:add(metric_value, buf(idx, value:len()), tonumber(value))
  idx = idx + value:len() + 1 -- +1 for |
  tree:add(metric_type, buf(idx, type:len()), get_metric_type_name(type))
  idx = idx + type:len()

  if idx >= buf:len() then return end

  for section in string.gmatch(buf(idx):string(), "[^|]+") do
    local section_buf = buf(idx + 1, section:len()) -- +1 for |
    local section_type = string.sub(section, 1, 1)
    if section_type == "@" then tree:add(metric_sampling, section_buf(1), tonumber(section_buf(1):string()))
    elseif section_type == "#" then tree:add(tags, section_buf(1), section_buf(1):string())
    end

    idx = idx + 1 + section:len() -- +1 for |
  end
end

function timestamp_to_nstime(ts_str)
  local ts = tonumber(ts_str)
  return NSTime.new(ts, 0)
end

function get_metric_type_name(metric_type)
  if metric_type == "c" then return "count"
  elseif metric_type == "g" then return "gauge"
  elseif metric_type == "ms" then return "timer"
  elseif metric_type == "h" then return "histogram"
  elseif metric_type == "s" then return "set"
  elseif metric_type == "d" then return "distribution"
  else return "invalid" end
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(8125, dogstatsd_protocol)
