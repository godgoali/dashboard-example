# Real-Time Dashboard Example

http://blog.sflow.com/2015/09/real-time-analytics-and-control.html

## To install

1. [Download sFlow-RT](https://sflow-rt.com/download.php)
2. Run command: `sflow-rt/get-app.sh sflow-rt dashboard-example`
3. Restart sFlow-RT

The dashboard now includes an *Attack List* panel that shows current UDP
flows. Each entry displays source and destination IP/port as well as the
traffic in bits per second and packets per second. Access the live attack
data using the REST endpoint `../scripts/metrics.js/attacks/json`.

When a UDP flow exceeds **10,000 packets per second**, a firewall rule is
automatically created via the `/filters` REST API. Rules are removed after
five minutes.

Use the browser console to manually test rule creation by calling the
`debugCreateRule('source_ip', 'destination_ip')` function. Replace the
arguments with the actual addresses you want to test. The dashboard logs
the request and response. The helper calls the `../scripts/metrics.js/filter`
endpoint on the sFlow-RT server which proxies the request to the firewall,
avoiding cross-origin errors in the browser.

For more information, visit:
http://www.sFlow-RT.com
