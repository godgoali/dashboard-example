# Real-Time Dashboard Example

http://blog.sflow.com/2015/09/real-time-analytics-and-control.html

## To install

1. [Download sFlow-RT](https://sflow-rt.com/download.php)
2. Run command: `sflow-rt/get-app.sh sflow-rt dashboard-example`
3. Restart sFlow-RT

The dashboard now includes an *Attack List* panel that shows current UDP
flows. Each entry displays source and destination IP/port as well as the
bandwidth in megabits per second and packets per second. Access the live
attack data using the REST endpoint `../scripts/metrics.js/attacks/json`.

For more information, visit:
http://www.sFlow-RT.com
