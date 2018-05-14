-- Prosody IM
--
-- mod_auth_ldap
-- 
-- Modded to use LDAP groups by Danixu86
-- Requires prosody 0.9+

local jid_split = require "util.jid".split;
local new_sasl  = require "util.sasl".new;
local lualdap   = require "lualdap";
local ldap      = module:require 'ldap';

local function ldap_filter_escape(s)
  return (s:gsub("[*()\\%z]", function(c) return ("\\%02x"):format(c:byte()) end));
end

-- Config Options
local module_host = module.host;
local params = module:context(module_host):get_option('ldap');

-- Default Options
params.hostname = params.hostname or 'localhost';
params.bind_dn =  params.bind_dn or '';
params.bind_password = params.bind_password or '';
params.mode = params.mode or "bind";
params.scope = params.scope or 'subtree';
local ldap_filter;
if params.user.filter and not params.user.filter:find("%$user") then
  ldap_filter = ldap.filter.combine_and(params.user.filter, "(" .. params.user.usernamefield .. "=$user)");
elseif not params.filter then
  ldap_filter  = "(" .. params.user.usernamefield .. "=$user)";
end
ldap_base = assert(params.user.basedn, "ldap user basedn is a required option for ldap");

-- Group vars
local gbasedn		= params.groups.basedn
local gmemberfield	= params.groups.memberfield;
local gnamefield	= params.groups.namefield;
local gufilter		= params.groups.userfilter or '(!(userAccountControl:1.2.840.113556.1.4.803:=2))';
local ggfilter		= params.groups.groupfilter or '';
-- Users vars
local uusernamefield	= params.user.usernamefield
local unamefield	= params.user.namefield

-- Admin groups
local admins_groups = {};
for _, config in ipairs(params.groups) do
  if config.admin then
    admins_groups[#admins_groups + 1] = config[gnamefield];
  end
end
module:log("debug", "Grupos administradores: %s", table.concat(admins_groups));

-- Initiate connection
local ld = nil;
module.unload = function() if ld then pcall(ld, ld.close); end end

function ldap_do_once(method, ...)
  if ld == nil then
    local err;
    ld, err = lualdap.open_simple(params.hostname, params.bind_dn, params.bind_password, params.use_tls);
    if not ld then return nil, err, "reconnect"; end
  end

  -- luacheck: ignore 411/success
  local success, iterator, invariant, initial = pcall(ld[method], ld, ...);
  if not success then ld = nil; return nil, iterator, "search"; end

  local success, dn, attr = pcall(iterator, invariant, initial);
  if not success then ld = nil; return success, dn, "iter"; end

  return dn, attr, "return";
end

function ldap_do(method, retry_count, ...)
  local dn, attr, where;
  for _=1,1+retry_count do
    dn, attr, where = ldap_do_once(method, ...);
    if dn or not(attr) then break; end -- nothing or something found
    module:log("warn", "LDAP: %s %s (in %s)", tostring(dn), tostring(attr), where);
    -- otherwise retry
  end
  if not dn and attr then
    module:log("error", "LDAP: %s", tostring(attr));
  end
  return dn, attr;
end

function get_user(username)
  module:log("debug", "get_user(%q)", username);
  module:log("debug", "LDAP filter: %s", ldap_filter);
  return ldap_do("search", 2, {
    base = ldap_base;
    scope = params.scope;
    sizelimit = 1;
    filter = ldap_filter:gsub("%$(%a+)", {
      user = ldap_filter_escape(username);
      host = module_host;
    });
  });
end

local provider = {};

function provider.create_user(username, password) -- luacheck: ignore 212
  return nil, "Account creation not available with LDAP.";
end

function provider.user_exists(username)
  return not not get_user(username);
end

function provider.set_password(username, password)
  local dn, attr = get_user(username);
  if not dn then return nil, attr end
  if attr.userPassword == password then return true end
  return ldap_do("modify", 2, dn, { '=', userPassword = password });
end

if params.mode == "getpasswd" then
  function provider.get_password(username)
    local dn, attr = get_user(username);
    if dn and attr then
      return attr.userPassword;
    end
  end

  function provider.test_password(username, password)
    return provider.get_password(username) == password;
  end

  function provider.get_sasl_handler()
    return new_sasl(module_host, {
      plain = function(sasl, username) -- luacheck: ignore 212/sasl
        local password = provider.get_password(username);
        if not password then return "", nil; end
        return password, true;
      end
    });
  end
elseif params.mode == "bind" then
  local function test_password(userdn, password)
    return not not lualdap.open_simple(params.hostname, userdn, password, params.use_tls);
  end

  function provider.test_password(username, password)
    local dn = get_user(username);
    if not dn then return end
    return test_password(dn, password)
  end

  function provider.get_sasl_handler()
    return new_sasl(module_host, {
      plain_test = function(sasl, username, password) -- luacheck: ignore 212/sasl
        return provider.test_password(username, password), true;
      end
    });
  end
else
  module:log("error", "Unsupported ldap mode %s", tostring(params.mode));
end

if #admins_groups > 0 then
  function provider.is_admin(jid)
    local username = jid_split(jid);
    module:log("debug", "Checking if user %s is admin", username);

    for _, group in pairs(admins_groups) do
      module:log("debug", "Checking if is in group %s", group);
      local gfilter = ldap.filter.combine_and("CN=" .. group, grfilter);
      module:log("debug", "Filter: %s", gfilter);
      for a, gmembers in ld:search { attrs = { gmemberfield }, base = gbasedn, scope = 'subtree', filter = gfilter } do
        for _, member in pairs(gmembers[gmemberfield]) do
          module:log("debug", "Member: %s", member);
          local usercn = member:match("[Cc][Nn]=(.-),[OoDd][UuCc]");
          local userdn = member:match("[Cc][Nn]=.-,([OoDd][UuCc].*)");
	  local ufilter = ldap.filter.combine_and("CN=" .. usercn, gufilter);
	  module:log("debug", "User filter: %s", ufilter);
          local _, userdata = ld:search { attrs = { uusernamefield }, base = userdn, scope = 'subtree', filter = ufilter }();

          if userdata and userdata[uusernamefield] then
            if userdata[uusernamefield] == username then
              module:log("debug", "user %s is admin", username);
              return true;
            end
          end
        end
      end
    end

    module:log("debug", "user %s is not admin", username);
    return nil;
  end
end

module:provides("auth", provider);
