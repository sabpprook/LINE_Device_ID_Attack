var dbFileElm = document.getElementById("db_file");
var auth_key_value = null;
var name_value = null;
var id_value = null;
var region_value = null;
var phone_value = null;

dbFileElm.onchange = () => {
    var f = dbFileElm.files[0];
    var r = new FileReader();
    r.onload = async () => {
        var arr = new Uint8Array(r.result);
        var db = new SQL.Database(arr);

        auth_key_value = get_setting(db, "PROFILE_AUTH_KEY");
        name_value = get_setting(db, "PROFILE_NAME");
        id_value = get_setting(db, "PROFILE_ID");
        region_value = get_setting(db, "PROFILE_REGION");
        phone_value = get_setting(db, "PROFILE_NORMALIZED_PHONE");

        console.log("PROFILE_AUTH_KEY: " + auth_key_value);
        console.log("PROFILE_NAME: " + name_value);
        console.log("PROFILE_ID: " + id_value);
        console.log("PROFILE_REGION: " + region_value);
        console.log("PROFILE_NORMALIZED_PHONE: " + phone_value);
        
        if (auth_key_value != null)
        {
            brute_force();
        }
    }
    r.readAsArrayBuffer(f);
}

showString = (str) => {
    document.getElementById("log").innerHTML = str;
}

appendString = (str) => {
    document.getElementById("log").innerHTML += str;
}

get_setting = (db, key) => {
    try {
        var result = db.exec("SELECT value FROM 'setting' WHERE key='" + key + "'");
        return result[0].values[0].toString();
    }
    catch(err) {
        showString(err.message);
        return null;
    }
}

brute_force = () => {
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
            {
                showAllKey(key);
            }

            appendString("ID: " + hex_string + "<br>");
            console.log("ID: " + hex_string);
        }

        // Show 10 result
        if (count == 10) {
            break;
        }
    }
    
    if (count == 0) {
        showString("Can not find correct Android ID!");
    }
}

java_string_hash = (s) => {
    var h = 0, l = s.length, i = 0;
    if ( l > 0 )
        while (i < l)
            h = (h << 5) - h + s.charCodeAt(i++) | 0;
    return h;
}

decrypt_setting = (value, key) => {
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

crazy_operation= (key, constant) => {
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

get_byte = (n) => {
    return n & 0xff;
}

is_profile_auth_key = (value) => {
    return value.match("^u[a-z0-9]{32}:[a-zA-Z0-9+]+$") != null;
}

showAllKey = (key) => {
    var auth_key = decrypt_setting(auth_key_value, key);
    var mid = auth_key.split(":")[0];
    var auth_key = auth_key.split(":")[1];
    var name = decrypt_setting(name_value, key);
    var id = decrypt_setting(id_value, key);
    var region = decrypt_setting(region_value, key);
    var phone = decrypt_setting(phone_value, key);

    appendString("User MID: " + mid + "<br>");
    appendString("Auth key: " + auth_key + "<br>");
    appendString("Name:     " + name + "<br>");
    appendString("LINE ID:  " + id + "<br>");
    appendString("Region:   " + region + "<br>");
    appendString("Phone:    " + phone + "<br><br>");

    console.log("User MID: " + mid);
    console.log("Auth key: " + auth_key);
    console.log("Name:     " + name);
    console.log("LINE ID:  " + id);
    console.log("Region:   " + region);
    console.log("Phone:    " + phone);
}