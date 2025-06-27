mitm proxy 
detect the sni from incoming packet generate CA for that domain and send the request 
next time we received same domain we use existing CA 
there will be a list of domains which are blacklisted
CA will be saved as text in vault after first successful request and if any TLS or weird error received we save it into log file