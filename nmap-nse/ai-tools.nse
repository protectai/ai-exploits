local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Performs an HTTP request to the root directory ("/") and "/v2/logging" on specified ports, checks the responses for specific strings, and identifies services based on these strings.
]]

author = "Your Name"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe", "discovery"}

portrule = shortport.port_or_service({4141, 4200, 5000, 5001, 8265, 8237, 54321, 54322, 43800, 80, 443, 8080, 8000, 8888, 8001, 8081}, {"http", "http-alt", "https", "https-alt"})

action = function(host, port)
  local results = {}
  local aiServiceFound = false

  -- Check root directory
  local response = http.get(host, port, "/")
  if response then
    if response.status and (response.status == 200 or response.status == 301 or response.status == 302) then
      if response.body then
        if response.body:find("<title>MLflow") then
          table.insert(results, "MLflow service found!\nCheck https://github.com/ProtectAI/AI-exploits for exploits.")
          aiServiceFound = true
        elseif response.body:find("<title>Ray Dashboard") then
          table.insert(results, "Ray Dashboard service found!\nCheck https://github.com/ProtectAI/AI-exploits for exploits.")
          aiServiceFound = true
        elseif response.body:find("<title>H2O Flow") then
          table.insert(results, "H2O Flow service found!\nCheck https://github.com/ProtectAI/AI-exploits for exploits.")
          aiServiceFound = true
        elseif response.body:find("<title>Kubeflow") then
          table.insert(results, "Kubeflow service found!\nCheck https://github.com/ProtectAI/AI-exploits for exploits.")
          aiServiceFound = true
        elseif response.body:find("<title>TensorBoard") then
          table.insert(results, "TensorBoard service found!")
          aiServiceFound = true
        elseif response.body:find("<title>ZenML") then
          table.insert(results, "ZenML service found!")
          aiServiceFound = true
        elseif response.body:find("<title>MLRun") then
          table.insert(results, "MLRun service found!")
          aiServiceFound = true
        elseif response.body:find("<title>MLServer") then
          table.insert(results, "MLServer service found!")
          aiServiceFound = true
        elseif response.body:find("<title>Weights ") then
          table.insert(results, "Weights & Biases service found!")
          aiServiceFound = true
        elseif response.body:find("<title>Aim</title>") then
          table.insert(results, "Aim service found!")
          aiServiceFound = true
        elseif response.body:find("<title>Neptune") then
          table.insert(results, "Neptune service found!")
          aiServiceFound = true
        elseif response.body:find("<title>Prefect") then
          table.insert(results, "Prefect service found!")
          aiServiceFound = true
        elseif response.body:find("<title>Kedro") then
          table.insert(results, "Kedro service found!")
          aiServiceFound = true
        elseif response.body:find("<title>Bento") then
          table.insert(results, "BentoML service found!")
          aiServiceFound = true
        end
      end
    end
  end

  -- Check /v2/logging if no other AI service was found
  if not aiServiceFound then
    local log_response = http.get(host, port, "/v2/logging")
    if log_response and log_response.status and (log_response.status == 200) and log_response.body and log_response.body:find('"log_file":') then
      table.insert(results, "Triton Inference Server service found!")
    end
  end

  if #results > 0 then
    return stdnse.format_output(true, results)
  else
    return nil
  end
end
