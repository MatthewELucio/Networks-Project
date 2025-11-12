@load base/protocols/ssl

# Domains to watch (regex patterns)
const llm_hosts: set[pattern] = {
    /(^|\.)chatgpt\.com$/,
    /(^|\.)openai\.com$/,
    /(^|\.)api\.openai\.com$/,
    /(^|\.)claude\.ai$/,
    /(^|\.)anthropic\.com$/,
    /(^|\.)gemini\.google\.com$/,
    /(^|\.)generativelanguage\.googleapis\.com$/
};

# Helper function
function matches_llm(h: string): bool
    {
    for (p in llm_hosts)
        if ( p in h )
            return T;
    return F;
}

# TLS handshake hook: SNI
event ssl_established(c: connection)
    {
    if ( c$ssl?$server_name && matches_llm(c$ssl$server_name) )
        print fmt("LLM_TLS_SNI %s %s:%s -> %s:%s SNI=%s",
                  network_time(),
                  c$id$orig_h, c$id$orig_p,
                  c$id$resp_h, c$id$resp_p,
                  c$ssl$server_name);
    }
