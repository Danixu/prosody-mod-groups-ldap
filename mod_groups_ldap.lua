-- Prosody IM
-- Copyright (C) 2008-2010 Matthew Wild
-- Copyright (C) 2008-2010 Waqas Hussain
--
-- This project is MIT/X11 licensed. Please see the
-- COPYING file in the source package for more information.
--
-- Modded to use LDAP groups by Danixu86


local groups;
local members;
local ldap = module:require 'ldap';

local jid, datamanager = require "util.jid", require "util.datamanager";
local jid_prep = jid.prep;

local module_host = module:get_host();

-- Manage cache
local CACHE_EXPIRY = 300;
local gettime = require 'socket'.gettime;
local last_fetch_time = 0;

function groups_update()
  local ld		= ldap.getconnection();
  -- Group vars
  local gbasedn		= params.groups.basedn
  local gmemberfield	= params.groups.memberfield;
  local gnamefield	= params.groups.namefield;
  local gufilter	= params.groups.userfilter or '(!(userAccountControl:1.2.840.113556.1.4.803:=2))';
  -- Users vars
  local ubasedn		= params.user.basedn
  local uusernamefield	= params.user.usernamefield
  local unamefield	= params.user.namefield

  groups = { default = {} };
  members = {};
  members[false] = {};

  module:log("debug", "Updating groups cache");
  for _, config in ipairs(params.groups) do
    module:log("debug", "New group: %s with name: %s", tostring(config[gnamefield]), tostring(config.name));
    groups[ config.name ] = {};

    if config.public then
      members[false][#members[false]+1] = config.name;
    end

    module:log("debug", "Adding users to group");
    local gfilter = "(&(objectClass=group)(CN=" .. config[gnamefield] .. "))";
    module:log("debug", "Getting group data: attrs=%s, base=%s, filter=%s", gmemberfield, gbasedn, gfilter);
    for a, gmembers in ld:search { attrs = { gmemberfield }, base = gbasedn, scope = 'subtree', filter = gfilter } do
      if members then
        for _, member in pairs(gmembers[gmemberfield]) do
          module:log("debug", "Processing member %s", member);
	  local cut = member:find(',OU') or member:find(',DC');
          local usercn = member:sub(4, cut - 1);
          local userdn = member:sub(cut + 1, -1);
          module:log("debug", "Getting user info from LDAP: base=%s, filter=%s", userdn, "(&" .. gufilter .. "(CN=" .. usercn .. "))");
          local _, userdata = ld:search { attrs = { uusernamefield }, base = userdn, scope = 'subtree', filter = "(&" .. gufilter .. "(CN=" .. usercn .. "))" }();
          if userdata and userdata[uusernamefield] then
            module:log("debug", "Adding user %s to group %s", userdata[uusernamefield], config.name);
            local jid = jid_prep( userdata[uusernamefield] .. "@" .. module.host );
            if jid then
              groups[config.name][jid] = usercn or false;
              module.log("debug", "User added");
            else
              module.log("diebug", "User has no jid");
            end
          end
        end
      end
    end
  end

  last_fetch_time = gettime();
  module:log("info", "Groups loaded successfully");
end


function inject_roster_contacts(event)
  local username, host= event.username, event.host;
  module:log("debug", "Injecting group members to roster");
  local bare_jid = username.."@"..host;
  if not members[bare_jid] and not members[false] then return; end -- Not a member of any groups

  local cache_time = params.cachetime or CACHE_EXPIRY;
  if last_fetch_time + cache_time < gettime() then
    groups_update();
  end

  local roster = event.roster;
  local function import_jids_to_roster(group_name)
    for jid in pairs(groups[group_name]) do
      -- Add them to roster
      module:log("debug", "processing jid %s in group %s", tostring(jid), tostring(group_name));
      if jid ~= bare_jid then
        if not roster[jid] then roster[jid] = {}; end
        roster[jid].subscription = "both";
        if groups[group_name][jid] then
          roster[jid].name = groups[group_name][jid];
        end
        if not roster[jid].groups then
          roster[jid].groups = { [group_name] = true };
        end
        roster[jid].groups[group_name] = true;
        roster[jid].persist = false;
      end
    end
  end

  -- Find groups this JID is a member of
  for group in pairs(groups) do
    module:log("debug", "Checking if user exists on group %s", group);
    if groups[group][bare_jid] ~= nil then
      module:log("debug", "Importing group %s as member", group);
      import_jids_to_roster(group);
    else
      module:log("debug", "User is not in group", group);
    end
  end

  -- Import public groups
  module:log("debug", "members[false]: %s", table.concat(members[false], ', '));
  if members[false] then
    for _, group_name in ipairs(members[false]) do
      module:log("debug", "Importing public group %s", group_name);
      import_jids_to_roster(group_name);
    end
  end

  if roster[false] then
    roster[false].version = true;
  end
end

function remove_virtual_contacts(username, host, datastore, data)
  module:log("debug", "remove_virtual_vontacts - username: %s, host: %s, datastore: %s, data: %s", username, host, datastore, data);
  if host == module_host and datastore == "roster" then
    local new_roster = {};
    for jid, contact in pairs(data) do
      for citem, cdata in pairs(contact) do
        module:log("debug", "Item: %s, Data: %s", citem, cdata);
      end
      if contact.persist ~= false then
        new_roster[jid] = contact;
      end
    end
    if new_roster[false] then
      new_roster[false].version = nil; -- Version is void
    end
    return username, host, datastore, new_roster;
  end

  return username, host, datastore, data;
end

function module.load()
  module:log("debug", "Loading groups_ldap module");
  params = module:get_option('ldap');
  if not params then return; end

  module:log("debug", "Adding rooster-load hook");
  module:hook("roster-load", inject_roster_contacts);
  module:log("debug", "Removing virtual contacts");
  datamanager.add_callback(remove_virtual_contacts);

  groups_update();
end

function module.unload()
  datamanager.remove_callback(remove_virtual_contacts);
end

-- Public for other modules to access
function group_contains(group_name, jid)
  return groups[group_name][jid];
end

