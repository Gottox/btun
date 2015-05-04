(function(w,urls) {
	var socks = [];
	var salt;
	var reconnecting = 0;

	function onmessage(ev) {
		for(var i = 0; i < socks.length; i++) {
			if(socks[i] != this)
				socks[i].send(ev.data);
		}
	}

	function connect(url) {
		var sock, l = w.location; 

		if(url == "") {
			return;
		} else if(url == '/') {
			url = (l.protocol == "https:" ? "wss://" : "ws://") + l.hostname + ":" + l.port;
		}
		try {
			sock = new w.WebSocket(url + "/" + salt, "ws");
		} catch(e) {
			return reconnect();
		}

		sock.onmessage = onmessage;
		sock.onclose = reconnect;
		socks.push(sock);
	}

	function init() {
		var i;
		salt = Math.random().toString(36).substring(7);
		reconnecting = 0;
		for(i = 0; i < urls.length; i++) {
			connect(urls[i]);
		}
	}

	function reconnect() {
		if(reconnecting)
			return;
		reconnecting = 1;
		for(i = 0; i < socks.length; i++)
			socks[i].close();
		setTimeout(init, 1000);
	}
	init();
})(window,["%s", "%s"]);
