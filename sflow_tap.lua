--
-- (C) 2017-18 - ntop.org
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
		    "sflow_245.ifspeed",
		    "sflow_245.ifinoct",
		    "sflow_245.ifoutoct",
		    "sflow.flow_sample.source_id_class",
		    "sflow.flow_sample.flow_record",
		    "eth.src","eth.dst",
		    "ip.src", "ip.dst"}) do
   required_fields[f] = Field.new(f)
end

local function sFlow_tap_factory()
   -- will hold all the dissected fields
   local all_fields
   -- this is going to be our counter
   local sflow_packets = 0
   -- here we will store all agents counters and flows
   local all_agents = {}

   local function set_agent_interface_counters(agent, if_idx, counters)
      if not all_agents[agent] then all_agents[agent] = {} end
      all_agents[agent][if_idx] = counters
   end

   -- Searches fields in order. When multiple fields with the same name are found
   -- then only the first field is returned
   local function search_field(field_name, start_pos)
      local pos = start_pos or 1

      for cur_pos = pos, #all_fields do
	 if field_name == get_string(all_fields[cur_pos].name) then
	    return cur_pos, all_fields[cur_pos]
	 end
      end
   end

   -- Searches a field and, if found, accesses and returns field value properly casted using fnct
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

   local function samples_iter()
      local pos_sflow, field_sflow             = search_field("sflow")
      local pos_num_samples, field_num_samples = search_field("sflow_245.numsamples", pos_sflow)

      if not field_num_samples then
	 return function() return nil end -- no samples (malformed packet?)
      end

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

   local function sample_records_iter(pos, which_records)
      -- multiple records can exist for the same flow sample or counter sample
      local pos_num_records, num_records = get_field_value_number(which_records, pos)

      if not num_records then
	 return function() return nil end -- no records (malformed packet?)
      end

      local cur_pos = pos_num_records
      local cur_record = 0

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

   local function process_counter_sample_record(agent, if_idx, pos)
      debug(string.format("COUNTER SAMPLE RECORD: %d if_idx: %d", pos, if_idx))
      local pos_enterprise, enterprise = get_field_value_number("sflow.enterprise",  pos)
      local pos_record_fmt, record_fmt = get_field_value_number("sflow_245.counters_record_format", pos_enterprise)

      -- enterprise == 0: standard sFlow
      -- record_fmt == 2: generic interface counters
      if enterprise == 0 and record_fmt == 1 then
	 local _, ifspeed  = get_field_value_string("sflow_245.ifspeed", pos_enterprise)
	 local _, ifinoct  = get_field_value_string("sflow_245.ifinoct", pos_enterprise)
	 local _, ifoutoct = get_field_value_string("sflow_245.ifoutoct", pos_enterprise)
	 -- ifspeed, inoct and outoct are of type hyper. Directly getting the value as number doesn't work
	 -- and it is required a double conversion first to string and then to number
	 ifinoct  = tonumber(ifinoct or 0)
	 ifoutoct = tonumber(ifoutoct or 0)
	 ifspeed  = tonumber(ifspeed or 0)

	 set_agent_interface_counters(agent, if_idx, {ifinoct = ifinoct, ifoutoct = ifoutoct, ifspeed = ifspeed})
	 debug(string.format("\tifinoct: %d ifoutoct: %d ifspeed: %d", ifinoct, ifoutoct, ifspeed))
      end
   end

   local function process_flow_sample_record(agent, pos)
      debug(string.format("FLOW SAMPLE RECORD: %d", pos))
      -- local pos_eth_src, eth_src = get_field_value_string("eth.src", pos)
      -- local pos_eth_dst, eth_dst = get_field_value_string("eth.dst", pos)
      -- debug(string.format("agent: %s\neth.src: %s\neth.dst: %s", agent or '', eth_src or '', eth_dst or ''))
   end

   local function process_counter_sample(agent, pos)
      -- The most significant byte of the source_id (sflow.counters_sample.source_id_type)
      -- is used to indicate the type of sFlowDataSource:
      -- 0 = ifIndex
      -- 1 = smonVlanDataSource
      -- 2 = entPhysicalEntry
      local _, source_id_type = get_field_value_number("sflow.counters_sample.source_id_type", pos)

      if source_id_type == 0 then -- ifIndex
	 debug(string.format("COUNTER SAMPLE: %d", pos))
	 local _, source_id_index = get_field_value_number("sflow.counters_sample.source_id_index", pos + 1)

	 for record_pos in sample_records_iter(pos + 2, "sflow.counters_sample.counters_records") do
	    process_counter_sample_record(agent, source_id_index, record_pos)
	 end

	 debug(string.format("source_id_type: %d\nsource_id_index: %d", source_id_type or 0, source_id_index or 0))
      end
   end

   local function process_flow_sample(agent, pos)
      -- see comments for process_counter_sample source_id_type that are equivalent
      local _, source_id_class = get_field_value_number("sflow.flow_sample.source_id_class", pos)

      if source_id_class == 0 then -- ifIndex
	 debug(string.format("FLOW SAMPLE: %d", pos))
	 local _, source_id_index = get_field_value_number("sflow.counters_sample.source_id_index", pos + 1)

	 for record_pos in sample_records_iter(pos + 2, "sflow.flow_sample.flow_record") do
	    process_flow_sample_record(agent, record_pos)
	 end
      end
   end

   local function process_sample(agent, pos)
      local pos_sample_type, field_sample_type = search_field("sflow_245.sampletype", pos)

      if field_sample_type then
	 local sample_type = get_number(field_sample_type.value)

	 if sample_type == 1 then     -- flow sample
	    process_flow_sample(agent, pos_sample_type)
	 elseif sample_type == 2 then -- counter sample
	    process_counter_sample(agent, pos_sample_type)
	 end
      end
   end

   -- first we declare the tap called "sflow tap" with the filter it is going to use
   local tap_sflow = Listener.new(nil, "sflow_245.version == 5")

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

      for sample_pos in samples_iter() do
	 process_sample(agent, sample_pos)
      end
   end

   -- this function will be called at the end of the capture run
   function tap_sflow.reset()
      sflow_packets = 0
      all_agents = {}
   end

   return {tap = tap_sflow, res = all_agents, sflow_packets = sflow_packets}
end


if gui_enabled() then
   local function sflow_counter_samples_menu()
      -- Declare the window we will use
      local tw = TextWindow.new("sFlow Counter Samples")
      local num_draws = 0

      -- Instantiate a new tap
      local sflow_counter_samples = sFlow_tap_factory()

      local function remove()
	 -- this way we remove the listener that otherwise will remain running indefinitely
	 sflow_counter_samples.tap:remove()
      end

      -- we tell the window to call the remove() function when closed
      tw:set_atclose(remove)

      sflow_counter_samples.tap.draw = function()
	 debug("drawing Counter samples!")
	 tw:clear()
	 tw:append("num_draws: " .. num_draws .. "\n");
	 num_draws = num_draws + 1
      end
   end

   register_menu("ntop/sFlow/Counters", sflow_counter_samples_menu, MENU_TOOLS_UNSORTED)
else
   -- TODO: no GUI
end


