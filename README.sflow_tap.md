# sflow_tap Wireshark Lua Plugin

sflow_tap is a Wireshark Lua plugin that runs on sFlow packets to
provide aggregated visibility on sFlow agents interfaces status and
load as well as on the top talkers (sources and destinations) that are
traversing the agents.

The plugin creates a `Listener.new` tap to receive only sFlow counter
samples or flow samples.

sflow_tap uses:
* Counter samples to calculate agent interfaces status, volumes of traffic
(INput and OUTput), throughput, and utilization percentage.
* Flow samples to calculate the top sources and the top destinations
  traversing every agent.

## Installation

Put the sflow_tap.lua file into the Wireshark plugins directory. To
determine the directory, open Wireshark, select 'About Wireshark' from
the menu, and chose the 'Folders' tab. Either 'Personal' or 'Global'
plugin directories can be used.

## Usage

Once the plugin is installed, two new menu items appear:
* Tools->ntop->sFlow->Counters
* Tools->ntop->sFlow->Talkers

A new Wireshark windows opens when selecting any of the two items. In
presence of sFlow traffic, the window dynamically updates to show
live information.
