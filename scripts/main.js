var dbFileElm = document.getElementById("db_file");
var logElm = document.getElementById("log");

var auth_key_value = null;
var name_value = null;
var id_value = null;
var region_value = null;
var phone_value = null;

dbFileElm.onchange = async function() {
	var f = dbFileElm.files[0];
	console.log(f);
    var r = new FileReader();
	console.log(r);
	r.onload = async function() {
		var arr = new Uint8Array(r.result);
    	var db = new SQL.Database(arr);
    	try {
        	db.exec("SELECT value FROM 'setting' WHERE key = 'PROFILE_AUTH_KEY'");
        	append_string(" OK!<br><br>");
    	}
    	catch(err) {
        	append_string("<br>" + err.message);
        	return;
    	}
    	
    	auth_key_value = get_setting(db, "PROFILE_AUTH_KEY");
        name_value = get_setting(db, "PROFILE_NAME");
        id_value = get_setting(db, "PROFILE_ID");
        region_value = get_setting(db, "PROFILE_REGION");
        phone_value = get_setting(db, "PROFILE_NORMALIZED_PHONE");
        
        console.log("PROFILE_AUTH_KEY:         " + auth_key_value);
        console.log("PROFILE_NAME:             " + name_value);
        console.log("PROFILE_ID:               " + id_value);
        console.log("PROFILE_REGION:           " + region_value);
        console.log("PROFILE_NORMALIZED_PHONE: " + phone_value);
        
        await delay(200);
        append_string("PROFILE_AUTH_KEY:" + nbsp(9) + auth_key_value + "<br>");
    	await delay(200);
        append_string("PROFILE_NAME:" + nbsp(13) + name_value + "<br>");
    	await delay(200);
        append_string("PROFILE_ID:" + nbsp(15) + id_value + "<br>");
    	await delay(200);
        append_string("PROFILE_REGION:" + nbsp(11) + region_value + "<br>");
    	await delay(200);
        append_string("PROFILE_NORMALIZED_PHONE:" + nbsp(1) + phone_value + "<br><br>");
        await delay(200);
        
	    append_string("Decrypting...<br><br>");
	    
        await brute_force();
	}
	show_string("Checking database...");
	r.readAsArrayBuffer(f);
}

function get_setting(db, key) {
    var result = db.exec("SELECT value FROM 'setting' WHERE key='" + key + "'");
    return result[0].values[0].toString();
}

async function brute_force() {
	var count = 0;
    for (var i = 0; i <= 0x1000; i++) {
        // TEST Android ID from 0000000000000000 to 0000000000001000
        var hex_string = ("0000000000000000" + (i).toString(16).toLowerCase()).slice(-16);
        var key = java_string_hash(hex_string);
        var auth_key_plaintext = decrypt_setting(auth_key_value, key);
        if (is_profile_auth_key(auth_key_plaintext))
        {
            count++;
            if (count == 1)
                await show_all_key(key);
            append_string("ID: " + hex_string + "<br>");
            console.log("ID: " + hex_string);
        }
        // Show 10 result
        if (count == 10)
            break;
    }
    if (count == 0)
        showString("Can not find correct Android ID!");
}

function java_string_hash(s) {
    var h = 0, l = s.length, i = 0;
    if ( l > 0 )
        while (i < l)
            h = (h << 5) - h + s.charCodeAt(i++) | 0;
    return h;
}

function decrypt_setting(value, key) {
    var ciphertext = Uint8Array.from(atob(value), c => c.charCodeAt(0));

    // AES ECB decrypt
    var aes_key = crazy_operation(key, 0xec4ba7);
    var aesEcb = new aesjs.ModeOfOperation.ecb(aes_key);
    var plaintext = aesEcb.decrypt(ciphertext);

    // Remove PKCS#7 padding
    var end = plaintext.length - plaintext[plaintext.length - 1];
    plaintext = plaintext.slice(0, end);

    // Convert byte array to UTF-8 string
    plaintext = new TextDecoder().decode(plaintext);

    return plaintext;
}

function crazy_operation(key, constant) {
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
        var k1 = ((i + 1) & (larr - 1));
        var l1 = constant * arr[k1] + k;
        var k = parseInt(l1 / 4294967296) & 0xFF;
        var i2 = l1 + k;

        if (i2 < k) {
            i2++;
            k++;
        }
        
        arr[k1] = get_byte(-2 - i2);
        i = k1;
    }

    return arr;
}

function get_byte(n) {
    return n & 0xff;
}

function is_profile_auth_key(value) {
    return value.match("^u[a-z0-9]{32}:[a-zA-Z0-9+]+$") != null;
}

async function show_all_key(key) {
    var auth_key = decrypt_setting(auth_key_value, key);
    var mid = auth_key.split(":")[0];
    var auth_key = auth_key.split(":")[1];
    var name = decrypt_setting(name_value, key);
    var id = decrypt_setting(id_value, key);
    var region = decrypt_setting(region_value, key);
    var phone = decrypt_setting(phone_value, key);
    
    console.log("User MID: " + mid);
    console.log("Auth key: " + auth_key);
    console.log("Name:     " + name);
    console.log("LINE ID:  " + id);
    console.log("Region:   " + region);
    console.log("Phone:    " + phone);
    
    append_string("User MID:" + nbsp(1) + mid + "<br>");
    await delay(200);
    append_string("Auth key:" + nbsp(1) + auth_key + "<br>");
    await delay(200);
    append_string("Name:" + nbsp(5) + name + "<br>");
    await delay(200);
    append_string("LINE ID:" + nbsp(2) + id + "<br>");
    await delay(200);
    append_string("Region:" + nbsp(3) + region + "<br>");
    await delay(200);
    append_string("Phone:" + nbsp(4) + phone + "<br><br>");
    await delay(200);
}

function show_string(str) {
    logElm.innerHTML = str;
}

function append_string(str) {
    logElm.innerHTML += str;
}

function nbsp(count) {
	var text = "";
	for (; count > 0; count--)
	    text += "&nbsp;";
	return text;
}

async function delay(duration) {
    return new Promise((resolve, reject) => {
        setTimeout(resolve, duration);
    });
}
