(function() {
var l = window.location;
var socks = [];
function setup(ii, addr) {
	var sock, i;
	if(addr == "")
		return;
	else if(addr == '/') {
		addr = (l.protocol == "https:" ? "wss://" : "ws://") + l.hostname + ":" + l.port;
	}
	try {
		sock = new WebSocket(addr, "ws");
	} catch(e) {
		setup(ii, addr);
	}
	sock.onmessage = function(ev) {
		for(i = 0; i < socks.length; i++) {
			f(i != ii && socks[i] && socks[i].readyState==1)
				socks[i].send(ev.data);
		}
	};
	sock.onclose = sock.onerror = function() {
		setup(ii, addr);
	};
	socks[ii] = sock;
}

for(var i = 0; i < arguments.length; i++) {
	setup(i, arguments[i])
}

})("%s", "%s");
