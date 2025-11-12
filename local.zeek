@load base/protocols/ssl
@load base/protocols/dns

redef exit_only_after_terminate = T;

# Very small, editable allowlist (add lines as needed)
const llm_domains: set[string] = {
  "chatgpt.com",
  "openai.com",
  "api.openai.com",
  "claude.ai",
  "anthropic.com",
  "gemini.google.com",
  "generativelanguage.googleapis.com"
};

event dns_response(c: connection, msg: dns_msg, ans: dns_answer, query: string, qtype: count, ttl: interval) &priority=5
{
  for (d in llm_domains)
    if ( query ends_with d )
      Log::write(Conn::LOG, c$conn);  # ensure conn logged
}

event ssl_established(c: connection)
{
  if ( c$ssl?$server_name )
    for (d in llm_domains)
      if ( c$ssl$server_name ends_with d )
        print fmt("LLM_TLS_MATCH %s %s -> %s SNI=%s",
                  network_time(), c$id$orig_h, c$id$resp_h, c$ssl$server_name);
}