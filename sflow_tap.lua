---
-- (C) 2018 - ntop.org
--
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software Foundation,
-- Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
--

local function get_string(finfo)
   local ok, val = pcall(tostring, finfo)
   if not ok then val = "(unknown)" end
   return val
end

local function get_number(finfo)
   local ok, val = pcall(tonumber, finfo)
   if not ok then val = nil end
   return val
end

-- Print contents of `tbl`, with indentation.
-- `indent` sets the initial level of indentation.
local function tprint(tbl, indent)
   if not indent then indent = 0 end
   for k, v in pairs(tbl) do
      formatting = string.rep("  ", indent) .. k .. ": "
      if type(v) == "table" then
	 print(formatting)
	 tprint(v, indent+1)
      else
	 print(formatting .. get_string(v))
      end
   end
end

-- Helper function to sort in ascending order
local function sort_asc(a,b)
  return (a < b)
end

-- Helper function to sort in descending order
local function sort_desc(a,b)
  return (a > b)
end

-- Iterate table pairs (key, value) ordered by key
local function pairs_by_keys(t, f)
  local a = {}

  for n in pairs(t) do table.insert(a, n) end

  if not f then
     f = sort_asc
  end

  table.sort(a, f)
  local i = 0      -- iterator variable
  local iter = function ()   -- iterator function
    i = i + 1
    if a[i] == nil then return nil
    else return a[i], t[a[i]]
    end
  end

  return iter
end

-- Iterate table pairs (key, value) ordered by value
local function pairs_by_values(t, f)
  local a = {}
  for n in pairs(t) do table.insert(a, n) end

  if not f then
     f = sort_asc
  end

  table.sort(a, function(x, y) return f(t[x], t[y]) end)
  local i = 0      -- iterator variable
  local iter = function ()   -- iterator function
    i = i + 1
    if a[i] == nil then return nil
    else return a[i], t[a[i]]
    end
  end
  return iter
end

-- Convert bytes into a human-readable representation
local function bytes_to_size(bytes)
   if bytes <= 0 then return "0.00 B" end

   local units = {"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB"}
   local digits = math.floor(math.log(bytes) / math.log(1024))

   local fmt = string.format("%.2f %s", bytes / (1024 ^ digits), units[digits + 1])

   return fmt
end

-- Convert a rate in bytes into a human-readable rate in bits per second
local function format_rate(bytes_rate)
   if bytes_rate <= 0 then return "0.00 B/s" end

   local bits_rate = bytes_rate * 8
   local units = {"b/s", "Kb/s", "Mb/s", "Gb/s", "Tb/s", "Pb/s", "Eb/s", "Zb/s"}
   local digits = math.floor(math.log(bits_rate) / math.log(1000))

   local fmt = string.format("%.2f %s", bits_rate / (1000 ^ digits), units[digits + 1])

   return fmt
end

-- Convert a ratio into a human-readable percentage
local function format_pct(ratio)
   ratio = ratio * 100
   if ratio < 0.01 then ratio = 0 end

   local fmt = string.format("%.2f %%", ratio)
   return fmt
end

-- Print all the contents of every field. All the field getters are iterated
-- and their values are printed.
local function print_all_fields(get_all)
   local getters = {"name", "offset", "len", "value"}

   for i, v in ipairs(all_fields or {}) do
      if get_all then
	 local mtb = getmetatable(v)
	 for gk in pairs(mtb.__getters) do
	    debug(string.format("%s: %s", gk, v[gk]))
	 end
      else
	 for _, gk in ipairs(getters) do
	    debug(string.format("%s: %s", gk, v[gk]))
	 end
      end
   end
end

-- These are the fields we are going to extract
-- They must be explicitly listed in order to tell wireshark to dissect them
local required_fields = {}
for _, f in ipairs({"sflow_245.version",
		    "sflow_245.sysuptime",
		    "sflow_245.agent",
		    "sflow_245.numsamples",
		    "sflow.enterprise",
		    "sflow_245.sampletype",
		    "sflow_5.sample_length",
		    "sflow_5.flow_data_length",
		    "sflow.counters_sample.sequence_number",
		    "sflow.counters_sample.source_id_type",
		    "sflow.counters_sample.source_id_index",
		    "sflow.counters_sample.counters_records",
		    "sflow_245.counters_record_format",
		    "sflow_245.flow_record_format",
		    "sflow_245.ifindex",
		    "sflow_245.ifspeed",
		    "sflow_245.ifinoct",
		    "sflow_245.ifoutoct",
		    "sflow_245.header_protocol",
		    "sflow.flow_sample.source_id_class",
		    "sflow.flow_sample.index",
		    "sflow.flow_sample.flow_record",
		    "sflow.flow_sample.sampling_rate",
		    "eth.type", "ip.src", "ip.dst", "ip.len"}) do
   required_fields[f] = Field.new(f)
end

-- this is going to be our counter
local sflow_packets = 0
-- here we will store all agents counters and flows
local agent_counters    = {}
local agent_flows       = {}

local function sFlow_tap_factory(tap_type)
   -- tap_type is either "counter_samples_tap" or "flow_samples_tap"
   --- to tap on counter samples or flow samples, respectively
   if tap_type ~= "counter_samples_tap" and tap_type ~= "flow_samples_tap" then
      tap_type = "counter_samples_tap"
   end

   -- will hold all the dissected fields
   local all_fields

   -- Calculate the sysuptime delta and return it in seconds
   local function sysuptime_delta_secs(new_sysuptime, old_sysuptime)
      local d_sysuptime = new_sysuptime - old_sysuptime

      if d_sysuptime >= 1000 then -- 1 sec
	 return d_sysuptime / 1000
      elseif d_sysuptime > 10 then
	 -- seems that there are buggy sflow agents that export the sysuptime in seconds
	 -- so we assume that if we have two samples for the same agent and source within less
	 -- than one second then the sysuptime is expressed in seconds rather than in milliseconds
	 return d_sysuptime
      end

      return 1
   end

   -- Populates a table that keeps interface counters for every agent, source id, and interface index.
   -- Counters include input and output octets, and the interface speed.
   local function set_agent_interface_counters(agent, sysuptime, source_id_index, ifindex, counters)
      if not agent_counters[agent] then agent_counters[agent] = {} end
      if not agent_counters[agent][source_id_index] then agent_counters[agent][source_id_index] = {} end
      if not agent_counters[agent][source_id_index][ifindex] then agent_counters[agent][source_id_index][ifindex] = {} end

      -- If there are previous values, then we can compute deltas and determine the link load of the interface
      local prev_counters = agent_counters[agent][source_id_index][ifindex]["counters"]
      local prev_sysuptime = agent_counters[agent][source_id_index][ifindex]["sysuptime"]
      if prev_counters and prev_sysuptime then
	 local deltas = {}

	 for c_name, c_val in pairs(counters) do
	    local prev_c = prev_counters[c_name]

	    if prev_c ~= nil then
	       local d = c_val - prev_c
	       local d_sysuptime = sysuptime_delta_secs(sysuptime, prev_sysuptime)

	       deltas[c_name] = d / d_sysuptime
	    end
	 end

	 agent_counters[agent][source_id_index][ifindex]["deltas"] = deltas
      end

      if prev_counters ~= nil then
	 -- debug(string.format("prev in: %d", prev_counters["ifinoct"] or nil))
	 -- debug(string.format("%d %d ifin: %d was: %d", source_id_index, ifindex, counters["ifinoct"], 10))
      end
      agent_counters[agent][source_id_index][ifindex]["counters"] = counters
      agent_counters[agent][source_id_index][ifindex]["sysuptime"] = sysuptime
   end

   -- Populates a table that keeps talkers for every agent and every source id. The sampling rate
   -- is used to scale up samples.
   local function set_agent_talkers(agent, sysuptime, source_id_index, sampling_rate, ip_src, ip_dst, ip_len)
      local src_delta, dst_delta
      local d_sysuptime, d_val

      if not agent_flows[agent] then agent_flows[agent] = {} end
      if not agent_flows[agent][source_id_index] then agent_flows[agent][source_id_index] = {sources = {}, dests = {}} end

      local prev_src = agent_flows[agent][source_id_index]["sources"][ip_src]
      local prev_dst = agent_flows[agent][source_id_index]["dests"][ip_dst]

      local src_tot =  agent_flows[agent][source_id_index]["sources"][ip_src]
      if src_tot then src_tot = src_tot["tot"] else src_tot = 0 end
      src_tot = src_tot + (ip_len * sampling_rate)

      if prev_src then
	 d_sysuptime = sysuptime_delta_secs(sysuptime, prev_src["sysuptime"])
	 d_val = src_tot - prev_src["tot"]
	 if d_val < 0 then d_val = 0 end
	 src_delta = d_val / d_sysuptime
      end

      agent_flows[agent][source_id_index]["sources"][ip_src] = {tot = src_tot, sysuptime = sysuptime, delta_tot = src_delta}

      local dst_tot =  agent_flows[agent][source_id_index]["dests"][ip_dst]
      if dst_tot then dst_tot = dst_tot["tot"] else dst_tot = 0 end
      dst_tot = dst_tot + (ip_len * sampling_rate)

      if prev_dst then
	 d_sysuptime = sysuptime_delta_secs(sysuptime, prev_dst["sysuptime"])
	 d_val = dst_tot - prev_dst["tot"]
	 if d_val < 0 then d_val = 0 end
	 dst_delta = d_val / d_sysuptime
      end

      agent_flows[agent][source_id_index]["dests"][ip_dst] = {tot = dst_tot, sysuptime = sysuptime, delta_tot = dst_delta}
   end

   -- Search fields in order. When multiple fields with the same name are found
   -- then only the first field is returned
   local function search_field(field_name, start_pos)
      local pos = start_pos or 1

      for cur_pos = pos, #all_fields do
	 if field_name == get_string(all_fields[cur_pos].name) then
	    return cur_pos, all_fields[cur_pos]
	 end
      end
   end

   -- Search a field and, if found, accesses and returns field value properly casted using fnct
   local function get_field_value(field_name, start_pos, fnct)
      local pos, field = search_field(field_name, start_pos)

      if field then
	 return pos, fnct(field.value)
      end
   end

   -- Searches a field and, if found, accesses and returns field value as a string
   local function get_field_value_string(field_name, start_pos)
      local pos, field = get_field_value(field_name, start_pos, get_string)

      if field then return pos, field  end
   end

   -- search a field and, if found, accesses and returns field value as a number
   local function get_field_value_number(field_name, start_pos)
      local pos, field = get_field_value(field_name, start_pos, get_number)

      if field then  return pos, field end
   end

   -- Iterate sflow samples in an sFlow packet
   local function samples_iter()
      local pos_sflow, field_sflow             = search_field("sflow")
      local pos_num_samples, field_num_samples = search_field("sflow_245.numsamples", pos_sflow)

      if not field_num_samples then
	 return function() return nil end -- no samples (malformed packet?)
      end

      -- sFlow packets can actually contain flow samples of sFlow traffic. This causes issues as wireshark
      -- would try to parse also the inner sFlow flow samples as if they were regular sFlow.
      -- To prevent inner sFlow flow samples to be taken by wireshark, we compute the expected offset of
      -- any sample, and return the sample only if its offset matches the expected offset.

      local cur_pos = pos_num_samples
      local expected_offset = get_number(field_num_samples.offset) + get_number(field_num_samples.len)

      return function()
	 while cur_pos <= #all_fields do
	    cur_pos = cur_pos + 1

	    local pos_sample_type, field_sample_type = search_field("sflow_245.sampletype",  cur_pos)
	    local pos_sample_len, field_sample_len   = search_field("sflow_5.sample_length", pos_sample_type)

	    if not field_sample_type then
	       return -- no more samples
	    end

	    cur_pos = pos_sample_type

	    if get_number(field_sample_type.offset) == expected_offset then
	       -- compute the next expected offset
	       expected_offset = get_number(field_sample_len.offset)
		  + get_number(field_sample_len.len)
		  + get_number(field_sample_len.value)

	       return pos_sample_type -- the begin of the sample in the all_fields array
	    end
	 end
      end
   end

   -- Iterate sFlow sample records within an sFlow sample
   local function sample_records_iter(pos, which_records)
      -- multiple records can exist for the same flow sample or counter sample
      local pos_num_records, num_records = get_field_value_number(which_records, pos)

      if not num_records then
	 return function() return nil end -- no records (malformed packet?)
      end

      local cur_pos = pos_num_records
      local cur_record = 0

      -- There is no need to compute an expected offset here as sample records are only
      -- iterated within an sFlow sample and samples_iter() ensures only good samples are chosen

      return function()
	 while cur_record < num_records and cur_pos <= #all_fields do
	    cur_pos = cur_pos + 1

	    -- the first offset of any record equals the offset of the enterprise field
	    local pos_enterprise, field_enterprise = search_field("sflow.enterprise",  cur_pos)
	    local pos_record_len, field_record_len = search_field("sflow_5.flow_data_length", pos_enterprise)

	    if not field_enterprise then
	       return -- no more sample records
	    end

	    cur_record = cur_record + 1
	    cur_pos = pos_enterprise

	    return pos_enterprise
	 end
      end
   end

   -- Process a counter sample record
   local function process_counter_sample_record(agent, sysuptime, source_id_index, pos)
--      debug(string.format("COUNTER SAMPLE RECORD: %d source_id_index: %d", pos, source_id_index))
      local pos_enterprise, enterprise = get_field_value_number("sflow.enterprise",  pos)
      local pos_record_fmt, record_fmt = get_field_value_number("sflow_245.counters_record_format", pos_enterprise)

      -- enterprise == 0: standard sFlow
      -- record_fmt == 1: generic interface counters
      if enterprise == 0 and record_fmt == 1 then
	 local _, ifindex  = get_field_value_number("sflow_245.ifindex", pos_enterprise)
	 local _, ifspeed  = get_field_value_string("sflow_245.ifspeed", pos_enterprise)
	 local _, ifinoct  = get_field_value_string("sflow_245.ifinoct", pos_enterprise)
	 local _, ifoutoct = get_field_value_string("sflow_245.ifoutoct", pos_enterprise)
	 -- ifspeed, inoct and outoct are of type hyper. Directly getting the value as number doesn't work
	 -- and it is required a double conversion first to string and then to number
	 ifinoct  = tonumber(ifinoct or 0)
	 ifoutoct = tonumber(ifoutoct or 0)
	 ifspeed  = tonumber(ifspeed or 0)

	 set_agent_interface_counters(agent, sysuptime, source_id_index, ifindex,
				      {ifinoct = ifinoct, ifoutoct = ifoutoct, ifspeed = ifspeed})
--	 debug(string.format("\tifinoct: %d ifoutoct: %d ifspeed: %d", ifinoct, ifoutoct, ifspeed))

      elseif enterprise == 0 and record_fmt == 4 then -- 100 BaseVG interface counters - see RFC 2020
	 -- TODO
      else
	 -- TODO
      end
   end

   -- Process a flow sample record
   local function process_flow_sample_record(agent, sysuptime, source_id_index, sampling_rate, pos)
--      debug(string.format("FLOW SAMPLE RECORD: %d source_id_index: %d sampling rate: %d", pos, source_id_index, sampling_rate))
      local pos_enterprise, enterprise = get_field_value_number("sflow.enterprise",  pos)
      local pos_record_fmt, record_fmt = get_field_value_number("sflow_245.flow_record_format", pos_enterprise)
      local pos_h_proto, h_proto       = get_field_value_number("sflow_245.header_protocol", pos_enterprise)

      -- enterprise == 0: standard sFlow
      -- record_fmt == 1: raw packet header
      -- h_proto == 1: ethernet
      if enterprise == 0 and record_fmt == 1 and h_proto == 1 then
	 local _, eth_type = get_field_value_number("eth.type", pos)
	 if eth_type == 2048 then -- IPv4 0x0800
	    local _, ip_src = get_field_value_string("ip.src", pos)
	    local _, ip_dst = get_field_value_string("ip.dst", pos)
	    local _, ip_len = get_field_value_number("ip.len", pos)

	    set_agent_talkers(agent, sysuptime, source_id_index, sampling_rate, ip_src, ip_dst, ip_len)
	 end
      else
	 -- TODO
      end
   end

   -- Process a counter sample with its records
   local function process_counter_sample(agent, sysuptime, pos)
      -- The most significant byte of the source_id (sflow.counters_sample.source_id_type)
      -- is used to indicate the type of sFlowDataSource:
      -- 0 = ifIndex
      -- 1 = smonVlanDataSource
      -- 2 = entPhysicalEntry
      local _, source_id_type = get_field_value_number("sflow.counters_sample.source_id_type", pos)

      if source_id_type == 0 then -- ifIndex
	 local _, source_id_index = get_field_value_number("sflow.counters_sample.source_id_index", pos + 1)
--	 debug(string.format("COUNTER SAMPLE: %d index: %d", pos, source_id_index))

	 for record_pos in sample_records_iter(pos + 2, "sflow.counters_sample.counters_records") do
	    process_counter_sample_record(agent, sysuptime, source_id_index, record_pos)
	 end
      end
   end

   -- Process a flow sample with its records
   local function process_flow_sample(agent, sysuptime, pos)
      -- see comments for process_counter_sample source_id_type that are equivalent
      local _, source_id_class = get_field_value_number("sflow.flow_sample.source_id_class", pos)

      if source_id_class == 0 then -- ifIndex
--	 debug(string.format("FLOW SAMPLE: %d", pos))
	 local _, source_id_index = get_field_value_number("sflow.flow_sample.index", pos + 1)
	 local _, sampling_rate =   get_field_value_number("sflow.flow_sample.sampling_rate", pos + 2)

	 for record_pos in sample_records_iter(pos + 2, "sflow.flow_sample.flow_record") do
	    process_flow_sample_record(agent, sysuptime, source_id_index, sampling_rate, record_pos)
	 end
      end
   end

   -- Process an sFlow sample
   local function process_sample(agent, sysuptime, pos)
      local pos_sample_type, field_sample_type = search_field("sflow_245.sampletype", pos)

      if field_sample_type then
	 local sample_type = get_number(field_sample_type.value)

	 if sample_type == 1 and tap_type == "flow_samples_tap" then -- flow sample
	    process_flow_sample(agent, sysuptime, pos_sample_type)
	 elseif sample_type == 2 and tap_type == "counter_samples_tap" then -- counter sample
	    process_counter_sample(agent, sysuptime, pos_sample_type)
	 end
      end
   end

   -- Declare the tap called "sflow tap" with the filter it is going to use
   local listener_filter = "sflow_245.version == 5"

   -- Filters are created on the basis of the tap type to avoid unnecessary processing
   if tap_type == "counter_samples_tap" then
      -- counter samples have type 2
      listener_filter = string.format("(%s) && (%s)", listener_filter, "sflow_245.sampletype == 2")
   elseif tap_type == "flow_samples_tap" then
      -- flow samples have type 1
      listener_filter = string.format("(%s) && (%s)", listener_filter, "sflow_245.sampletype == 1")
   end

   debug(string.format("creating tap with filter: '%s'", listener_filter))
   local tap_sflow = Listener.new(nil, listener_filter)

   -- this function is going to be called once each time the filter of the tap matches
   function tap_sflow.packet(pinfo, tvb, ip)
      -- local ip_src, ip_dst = tostring(ip.ip_src), tostring(ip.ip_dst)
      sflow_packets = sflow_packets + 1
      all_fields = { all_field_infos() }

      local _, version = get_field_value_string("sflow_245.version")
      if not version or version ~= "5" then
	 return -- not sFlow v5
      end

      local _, agent = get_field_value_string("sflow_245.agent")
      local _, sysuptime = get_field_value_string("sflow_245.sysuptime")

      for sample_pos in samples_iter() do
	 process_sample(agent, sysuptime, sample_pos)
      end
   end

   -- this function will be called at the end of the capture run
   function tap_sflow.reset()
      sflow_packets     = 0
      agent_counters    = {}
      agent_flows       = {}
   end

   return {tap = tap_sflow, res = agent_counters, sflow_packets = sflow_packets}
end

-- Returns an output function that can be used either within the wireshark gui as
-- well as directly from tshark. This make the plugin more general as it can be used
-- in the two modes.
local function get_output_function(text_window)
   local cleared = false
   local tw = text_window

   return function(what)
      if tw then
	 if not cleared then
	    tw:clear()
	    cleared = true
	 end

	 tw:append(what.."\n")
      else
	 debug(what)
      end
   end
end

-- Draw counters statistics
local function draw_counters(text_window)
   local output = get_output_function(text_window)

   for agent, agent_data in pairs_by_keys(agent_counters) do
      local tot_ifinoct       = 0
      local tot_ifoutoct      = 0
      local tot_ifinoct_rate  = 0
      local tot_ifoutoct_rate = 0

      output(string.format("agent: %s", agent))
      output(string.format("%14s %14s %14s %14s %14s %14s",
			      "INTERFACE",
			      "IN BYTES", "OUT BYTES",
			      "IN RATE", "OUT RATE", "UTILIZATION"))

      for source_id, source_vals in pairs_by_keys(agent_data) do
	 -- do not print the source id as it is uncommon to have
	 -- multiple source ids for the same interface
	 -- output(string.format("%s (source_id: %d):", agent, source_id))
	 for ifindex, if_vals in pairs_by_keys(source_vals) do
	    local counter_vals = if_vals["counters"]
	    local delta_vals = if_vals["deltas"]

	    if counter_vals then
	       local line
	       local ifspeed  = counter_vals.ifspeed
	       local ifinoct  = counter_vals.ifinoct  or 0
	       local ifoutoct = counter_vals.ifoutoct or 0

	       if ifinoct > 0 or ifoutoct > 0 then
		  line = string.format("%14s %14s %14s",
				       tostring(ifindex),
				       bytes_to_size(ifinoct),
				       bytes_to_size(ifoutoct))

		  tot_ifinoct  = tot_ifinoct  + ifinoct
		  tot_ifoutoct = tot_ifoutoct + ifoutoct

		  if delta_vals then
		     local delta_ifinoct  = delta_vals.ifinoct  or 0
		     local delta_ifoutoct = delta_vals.ifoutoct or 0
		     if delta_ifinoct > 0 or delta_ifoutoct > 0 then
			line = line..string.format(" %14s %14s",
						   format_rate(delta_ifinoct),
						   format_rate(delta_ifoutoct))

			tot_ifinoct_rate  = tot_ifinoct_rate  + delta_ifinoct
			tot_ifoutoct_rate = tot_ifoutoct_rate + delta_ifoutoct

			if ifspeed and ifspeed > 0 then
			   local utilization_in  = 8 * delta_ifinoct  / ifspeed
			   local utilization_out = 8 * delta_ifoutoct / ifspeed
			   local utilization = utilization_in

			   if utilization_out > utilization_in then
			      utilization = utilization_out
			   end
			   line = line..string.format(" %14s", format_pct(utilization))
			end
		     end
		  end
	       end

	       if line then
		  output(line)
	       end
	    end
	 end
      end
      output(string.format("%14s %14s %14s %14s %14s",
			      "TOTAL",
			      bytes_to_size(tot_ifinoct),
			      bytes_to_size(tot_ifoutoct),
			      format_rate(tot_ifinoct_rate),
			      format_rate(tot_ifoutoct_rate)))
      output("")
   end
end

-- Draw talkers statistics
local function draw_talkers(text_window)
   local output = get_output_function(text_window)

   for agent, agent_data in pairs_by_keys(agent_flows) do
      local all_srcs = {}
      local all_dsts = {}
      local all_src_rates = {}
      local all_dst_rates = {}
      local top_srcs = {}
      local top_dsts = {}
      local max_top = 5
      local cur_top

      output(string.format("agent: %s", agent))
      output(string.format("%16s %16s %16s %16s %16s %16s",
			      "SOURCE", "SOURCE BYTES", "SOURCE RATE",
			      "DEST", "DEST BYTES", "DEST RATE"))

      for source_id, source_vals in pairs_by_keys(agent_data) do
	 -- iterate over sources
	 -- consider at most one source for every host
	 -- if multiple sources exist for an host, take the one with the greatest value
	 -- output(string.format("%s (source_id: %d):", agent, source_id))
	 for src, vals in pairs(source_vals["sources"]) do
	    local bytes = vals["tot"]
	    local rate = vals["delta_tot"]
	    if not all_srcs[src] or all_srcs[src] < bytes then
	       all_srcs[src] = bytes
	       all_src_rates[src] = rate
	    end
	 end
	 for dst, vals in pairs(source_vals["dests"]) do
	    local bytes = vals["tot"]
	    local rate = vals["delta_tot"]
	    if not all_dsts[dst] or all_dsts[dst] < bytes then
	       all_dsts[dst] = bytes
	       all_dst_rates[dst] = rate
	    end
	 end
      end

      cur_top = 1
      for src, bytes in pairs_by_values(all_srcs, sort_desc) do
	 top_srcs[#top_srcs + 1] = {src = src, bytes = bytes}
	 if cur_top == max_top then
	    break
	 end
	 cur_top = cur_top + 1
      end

      cur_top = 1
      for dst, bytes in pairs_by_values(all_dsts, sort_desc) do
	 top_dsts[#top_dsts + 1] = {dst = dst, bytes = bytes}
	 if cur_top == max_top then
	    break
	 end
	 cur_top = cur_top + 1
      end

      for i = 1,max_top do
	 local line
	 if top_srcs[i] then
	    local src = top_srcs[i]["src"]
	    line = string.format("%16s %16s %16s",
				 src, bytes_to_size(top_srcs[i]["bytes"]), format_rate(all_src_rates[src] or 0))
	 elseif top_dsts[i] then
	    line = string.format("%16s %16s %16s", "", "", "") -- preserve line indentation
	 end

	 if top_dsts[i] then
	    local dst = top_dsts[i]["dst"]
	    line = string.format("%s %16s %16s %16s",
				 line, dst, bytes_to_size(top_dsts[i]["bytes"]), format_rate(all_dst_rates[dst] or 0))
	 elseif top_srcs[i] then
	    line = string.format("%s %16s %16s %16s", line, "", "", "") -- preserve line indentation
	 end

	 if line then
	    output(line)
	 end
      end
      output("")
   end
end

if gui_enabled() then
   local function sflow_counter_samples_menu()
      -- Declare the window we will use
      local tw = TextWindow.new("sFlow Counters")

      -- Instantiate a new tap
      local sflow_counter_samples = sFlow_tap_factory("counter_samples_tap")
      local res = sflow_counter_samples.res

      local function remove()
	 -- this way we remove the listener that otherwise will remain running indefinitely
	 sflow_counter_samples.tap:remove()
      end

      -- we tell the window to call the remove() function when closed
      tw:set_atclose(remove)

      sflow_counter_samples.tap.draw = function()
	 draw_counters(tw)
      end

      retap_packets()
   end

   local function sflow_flow_samples_menu()
      -- Declare the window we will use
      local tw = TextWindow.new("sFlow Top Talkers")

      -- Instantiate a new tap
      local sflow_flow_samples = sFlow_tap_factory("flow_samples_tap")
      local res = sflow_flow_samples.res

      local function remove()
	 -- this way we remove the listener that otherwise will remain running indefinitely
	 sflow_flow_samples.tap:remove()
      end

      -- we tell the window to call the remove() function when closed
      tw:set_atclose(remove)

      sflow_flow_samples.tap.draw = function()
	 draw_talkers(tw)
      end

      retap_packets()
   end

   register_menu("ntop/sFlow/Talkers",  sflow_flow_samples_menu,    MENU_TOOLS_UNSORTED)
   register_menu("ntop/sFlow/Counters", sflow_counter_samples_menu, MENU_TOOLS_UNSORTED)
else -- no GUI
   local sflow_counter_samples = sFlow_tap_factory("counter_samples_tap")
   sflow_counter_samples.tap.draw = function()
      draw_counters()
   end

   local sflow_flow_samples = sFlow_tap_factory("flow_samples_tap")
   sflow_flow_samples.tap.draw = function()
      draw_talkers()
   end
end
