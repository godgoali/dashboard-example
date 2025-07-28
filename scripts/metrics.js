// author: InMon Corp.
// version: 0.1
// date: 9/23/2015
// description: sFlow-RT Real-time Dashboard Example
// copyright: Copyright (c) 2015 InMon Corp.

include(scriptdir() + '/inc/trend.js');

var trend = new Trend(300,1);
var points;

var SEP = '_SEP_';
var FLOW_INTERVAL = 2; // seconds

// firewall REST API details
var FIREWALL_POST_URL = 'http://192.168.10.102:8080/fites';
var FIREWALL_DELETE_URL = 'http://192.168.10.102:8080/filters';
var FIREWALL_TOKEN = 'changeme';
var FIREWALL_DEBUG = true;

function fwLog(msg) {
  if(FIREWALL_DEBUG) logInfo('FWDBG ' + msg);
}

// define flows, prepend application name to avoid name clashes with other apps
setFlow('dashboard_example_bytes', {value:'bytes',t:FLOW_INTERVAL, fs: SEP});
setFlow('dashboard_example_stack', {keys:'stack', value:'bytes', n:10, t:FLOW_INTERVAL, fs:SEP});
// capture udp flows for attack visibility
setFlow('dashboard_example_ddos',
  {keys:'ipsource,udpsourceport,ipdestination,udpdestinationport',
   value:'bytes', n:20, t:FLOW_INTERVAL, fs:SEP, filter:'ipprotocol=17'});
setFlow('dashboard_example_ddos_pkts',
  {keys:'ipsource,udpsourceport,ipdestination,udpdestinationport',
   value:'frames', n:20, t:FLOW_INTERVAL, fs:SEP, filter:'ipprotocol=17'});

// flow and threshold for automatic firewall mitigation
setFlow('udp_ddos', {
  keys: 'ipdestination,ipsource,udpdestinationport',
  value: 'frames',
  filter: 'direction=ingress&ipprotocol=17&udpsourceport!=0',
  t: FLOW_INTERVAL
});

// Trigger when more than 10,000 packets per second are seen for a flow
// FLOW_INTERVAL is two seconds, so threshold value is 10kpps * 2 seconds
setThreshold('udp_ddos', {
  metric: 'udp_ddos',
  value: 20000,
  byFlow: true,
  timeout: 30
});

var activeRules = {};  // Format: key = sip-dip -> value = idx

var other = '-other-';
function calculateTopN(metric,n,minVal,total_bps) {     
  var total, top, topN, i, bps;
  top = activeFlows('ALL',metric,n,minVal,'sum');
  var topN = {};
  if(top) {
    total = 0;
    for(i in top) {
      bps = top[i].value * 8;
      topN[top[i].key] = bps;
      total += bps;
    }
    if(total_bps > total) topN[other] = total_bps - total;
  }
  return topN;
}

setIntervalHandler(function(now) {
  var res, total_bps;

  points = {};

  res = metric('ALL','sum:dashboard_example_bytes,sum:ifinoctets,ifoutoctets');
  points['bps'] = 0;
  points['bps_in'] = 0;
  points['bps_out'] = 0;
  if(res && res.length && res.length >= 3) {
    if(res[0].metricValue) points['bps'] += 8 * res[0].metricValue;
    if(res[1].metricValue) points['bps_in'] += 8 * res[1].metricValue;
    if(res[2].metricValue) points['bps_out'] += 8 * res[2].metricValue;
  }
  points['top-5-protocols'] = calculateTopN('dashboard_example_stack',5,1,points.bps);
  trend.addPoints(now,points);
},1);

setHttpHandler(function(req) {
  var result, key, name, path = req.path;
  if(!path || path.length == 0) throw "not_found";
     
  switch(path[0]) {
    case 'trend':
      if(path.length > 1) throw "not_found";
      result = {};
      result.trend = req.query.after ? trend.after(parseInt(req.query.after)) : trend;
      break;
    case 'attacks':
      if(path.length > 1) throw "not_found";
      var topBytes = activeFlows('ALL','dashboard_example_ddos',20,0,'sum');
      var topPkts = activeFlows('ALL','dashboard_example_ddos_pkts',20,0,'sum');
      var pktMap = {};
      result = [];
      if(topPkts) {
        for(var j = 0; j < topPkts.length; j++) {
          pktMap[topPkts[j].key] = topPkts[j].value;
        }
      }
      if(topBytes) {
        for(var i = 0; i < topBytes.length; i++) {
          var key = topBytes[i].key;
          var fields = key.split(SEP);
          result.push({
            ipsource: fields[0],
            udpsourceport: fields[1],
            ipdestination: fields[2],
            udpdestinationport: fields[3],
            bps: 8 * topBytes[i].value,
            pps: pktMap[key] ? Math.round(pktMap[key] / FLOW_INTERVAL) : 0
          });
        }
      }
      break;
    case 'filter':
      if(path.length > 1) throw 'not_found';
      var sip, dip;
      if(req.method && req.method.toUpperCase() === 'POST') {
        try {
          var body = req.body || req.data || '';
          if(body) {
            var obj = JSON.parse(body);
            sip = obj.sip;
            dip = obj.dip;
          }
        } catch(e) {
          throw 'bad_request';
        }
      } else {
        sip = req.query.sip;
        dip = req.query.dip;
      }
      if(!sip || !dip) throw 'bad_request';
      var payload = {enabled:true, log:true, action:0, sip:sip, dip:dip};
      var headers = {
        'Authorization': 'Bearer ' + FIREWALL_TOKEN,
        'Content-Type': 'application/json'
      };
      fwLog('PROXY POST ' + FIREWALL_POST_URL + ' payload=' + JSON.stringify(payload));
      var r = http(FIREWALL_POST_URL, 'POST', JSON.stringify(payload), 'application/json', headers);
      fwLog('PROXY RESP ' + r);
      result = JSON.parse(r);
      break;
    case 'metric':
      if(path.length == 1) result = points;
      else {
        if(path.length != 2) throw "not_found";
        if(points.hasOwnProperty(path[1])) result = points[path[1]];
        else throw "not_found";
      }
      break;
    default: throw 'not_found';
  } 
  return result;
});

setEventHandler(function(evt) {
  var parts = evt.flowKey.split(',');
  var dip = parts[0];
  var sip = parts[1];

  var ruleKey = sip + '-' + dip;
  if (activeRules[ruleKey]) {
    logInfo("\u23F1\uFE0F Rule sudah aktif untuk " + ruleKey);
    return;
  }

  var payload = {
    enabled: true,
    log: true,
    action: 0,
    sip: sip,
    dip: dip
  };

  // firewall REST API endpoint and token
  var postUrl = FIREWALL_POST_URL;
  var delBase = FIREWALL_DELETE_URL;
  var token = FIREWALL_TOKEN;
  var headers = {
    "Authorization": "Bearer " + token,
    "Content-Type": "application/json"
  };

  fwLog('POST ' + postUrl + ' payload=' + JSON.stringify(payload));

  try {
    var response = http(postUrl, 'POST', JSON.stringify(payload), 'application/json', headers);
    fwLog('RESPONSE ' + response);
    var obj = JSON.parse(response);

    if (obj && obj.result === 'ok' && obj.idx !== undefined) {
      var idx = obj.idx;
      activeRules[ruleKey] = idx;
      logInfo("\u2705 Rule dibuat untuk " + ruleKey + " dengan idx: " + idx);

      setTimeout(function() {
        var delUrl = delBase + '/' + idx;
        try {
          http(delUrl, 'DELETE', null, null, headers);
          fwLog('DELETE ' + delUrl);
          logInfo("\u1F5D1\uFE0F Rule auto-unban (DELETE) untuk " + ruleKey + " dengan idx: " + idx);
          delete activeRules[ruleKey];
        } catch (e) {
          logWarning("\u274C Gagal hapus rule: " + delUrl + " \u2192 " + e);
        }
      }, 5 * 60 * 1000);

    } else {
      logWarning("\u274C Format response tidak sesuai: " + response);
    }

  } catch (e) {
    logWarning("\u274C Error POST rule: " + e);
  }

}, ['udp_ddos']);

