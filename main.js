var dbFileElm = document.getElementById("db_file");
var auth_key_value = null;

get_byte = function(n) {
	return n & 0xff;
};

is_profile_auth_key = function(value) {
	return value.match("^u[a-z0-9]{32}:[a-zA-Z0-9+]+$") != null;
};

crazy_operation= function(key, constant) {
	var arr = new Uint8Array(16);
	arr[0] = get_byte(key)
	arr[1] = get_byte(key - 71)
	arr[2] = get_byte(key - 142)
		
	for (i = 3; i < 16; i++) {
		arr[i] = get_byte(i ^ (0xffffffb9 ^ (arr[i - 3] ^ arr[i - 2])));
	}
	
	if (constant < 2 && constant > -2) {
		constant = 0xfffffffffffb389d + 0xd2dfaf * constant;
	}

	for (x = 0, i = 0, k = -7, larr = arr.length; x < larr; x++) {
		k1 = ((i + 1) & (larr - 1));
		l1 = constant * arr[k1] + k;
		k = parseInt(l1 / 4294967296) & 0xFF;
		i2 = l1 + k;

		if (i2 < k) {
			i2++;
			k++;
		}
		
		arr[k1] = get_byte(-2 - i2);
		i = k1;
	}
	
	return arr;
};

decrypt_setting = function(value, key) {
	var ciphertext = Uint8Array.from(atob(value), c => c.charCodeAt(0));
	//console.log(ciphertext);
	
	var aes_key = crazy_operation(key, 0xec4ba7);
	//console.log(aes_key);
	
	var aesEcb = new aesjs.ModeOfOperation.ecb(aes_key);
	var plaintext = aesEcb.decrypt(ciphertext);
	//console.log(plaintext);
	
	var end = plaintext.length - plaintext[plaintext.length - 1];
	plaintext = plaintext.slice(0, end);
	//console.log(plaintext);
	
	plaintext = new TextDecoder().decode(plaintext);
	//console.log(plaintext);
	
	return plaintext;
};

java_string_hash = function(s) {
	var h = 0, l = s.length, i = 0;
	if ( l > 0 )
		while (i < l)
			h = (h << 5) - h + s.charCodeAt(i++) | 0;
	return h;
};

brute_force = function() {
	for (var i = 0; i <= 0xFFFF; i++) {
		var hex_string = ("0000000000000000" + (i).toString(16).toLowerCase()).slice(-16);
		var key = java_string_hash(hex_string);
		//console.log("TESTING: " + hex_string);
		var auth_key_plaintext = decrypt_setting(auth_key_value, key);
		if (is_profile_auth_key(auth_key_plaintext))
		{
			console.log("CORRECT: " + hex_string);
			showString("Android ID: " + hex_string);
			i = 0x666666;
		}
		//console.log("Can not find correct Android ID!");
		if (i == 0xFFFF) {
			showString("Can not find correct Android ID!");
		}
	}
};

showString = function(str) {
	document.getElementById("reverse").innerHTML = str;
}

dbFileElm.onchange = function() {
	var f = dbFileElm.files[0];
	var r = new FileReader();
	r.onload = function() {
		console.log("-- stage 1: read 'PROFILE_AUTH_KEY' from naver_line database.");
		try {
			var Uints = new Uint8Array(r.result);
			var db = new SQL.Database(Uints);
			var result = db.exec("SELECT value FROM 'setting' WHERE key='PROFILE_AUTH_KEY'");
			auth_key_value = result[0].values[0].toString();
		}
		catch(err) {
			auth_key_value = null;
			showString(err.message);
			//console.log(err.message);
		}
		console.log(auth_key_value);
		if (auth_key_value != null)
		{
			console.log("-- stage 2: Brute-force to reverse Android ID.");
			brute_force();
		}
	}
	r.readAsArrayBuffer(f);
}
