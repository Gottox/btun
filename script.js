(function() {
var l = window.location;
var socks = [];
function setup(ii, addr) {
	var sock, i, closing = false;
	if(addr == "")
		return;
	else if(addr == '/') {
		addr = (l.protocol == "https:" ? "wss://" : "ws://") + l.hostname + ":" + l.port;
	}
	try {
		sock = new WebSocket(addr, "ws");
	} catch(e) {
		console.log(e);
		return setTimeout(function() {
			setup(ii, addr);
		}, 500);
	}
	sock.onmessage = function(ev) {
		for(i = 0; i < socks.length; i++) {
			if(i != ii && socks[i] && socks[i].readyState==1)
				socks[i].send(ev.data);
		}
	};
	sock.onclose = sock.onerror = function() {
		for(i = 0; i < socks.length; i++) {
			if(i != ii && socks[i] && socks[i].readyState<=1)
				socks[i].close();
		}
		if(!closing)
			setup(ii, addr);
		closing = true;
	};
	socks[ii] = sock;
}

for(var i = 0; i < arguments.length; i++) {
	setup(i, arguments[i])
}

})("%s", "%s");
