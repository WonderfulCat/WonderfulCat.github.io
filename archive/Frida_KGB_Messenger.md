---
layout: default
---

#### 1. 第一个Activity有2个检测点:
- System.getProperty("user.home") 
- System.getenv("USER") 


```java
    @Override  
    public void onCreate(Bundle bundle) {
        String property = System.getProperty("user.home");
        String str = System.getenv("USER");
        if (property == null || property.isEmpty() || !property.equals("Russia")) {
            a("Integrity Error", "This app can only run on Russian devices.");
            return;
        }
  
        if (str == null || str.isEmpty() || !str.equals(getResources().getString(R.string.User))) {
            a("Integrity Error", "Must be on the user whitelist.");
        } else {
            a.a(this);
            startActivity(new Intent(this, (Class<?>) LoginActivity.class));
        }
    }
```


 1.1 hook System.getProperty
```javascript
Java.perform(() => {
    var stringCls = Java.use('java.lang.String');

    var systemCls = Java.use('java.lang.System');
    systemCls.getProperty.overload('java.lang.String').implementation = function (val) {
        var ret = this.getProperty(val);	
        console.log("user.home : " + ret);
        var newString = stringCls.$new("Russia");	//返回Russia
        return newString;
    }
});
```
1.2 查找到 getResources().getString(R.string.User) 字符串
```xml
 <string name="User">RkxBR3s1N0VSTDFOR180UkNIM1J9Cg==</string> // flag
```
1.3 hook System.getenv("USER")
```javascript
    systemCls.getenv.overload('java.lang.String').implementation = function (val) {
        var newString = stringCls.$new("RkxBR3s1N0VSTDFOR180UkNIM1J9Cg==");
        return newString;
    }
```

#### 2. 第二个Activity有2个检测点:
```java
    public void onLogin(View view) {
        EditText editText = (EditText) findViewById(R.id.login_username);
        EditText editText2 = (EditText) findViewById(R.id.login_password);
        this.mw_loginActivity_str_username = editText.getText().toString();
        this.mw_loginActivity_str_passwd = editText2.getText().toString();
        if (this.mw_loginActivity_str_username == null || this.mw_loginActivity_str_passwd == null || this.mw_loginActivity_str_username.isEmpty() || this.mw_loginActivity_str_passwd.isEmpty()) {
            return;
        }
  
        if (!this.mw_loginActivity_str_username.equals(getResources().getString(R.string.username))) {
            Toast.makeText(this, "User not recognized.", 0).show();
            editText.setText("");
            editText2.setText("");
        } else if (mw_loginActivity_CheckPSWD()) {
            mw_loginActivity_ToastShowFlag();
            startActivity(new Intent(this, (Class<?>) MessengerActivity.class));
        } else {
            Toast.makeText(this, "Incorrect password.", 0).show();
            editText.setText("");
            editText2.setText("");
        }
    }
```
2.1 字符串查找得到 username
```xml
 <string name="username">codenameduchess</string>
```
2.2 密码使用MD5加密
Google搜索codenameduchess password是一个动画片里面中的密码:==guest== (离谱)
这里如果使用frida hook函数破解的话会得不到第二个Flag. 第二个Flag需要用户名和密码来解码.


#### 3. 第三个Activity有2个检测点:
```java
	//第一个检测
  	if (mw_messengerAcitivty_EncodeInputText1(inputText.toString()).equals(this.mw_messengerActivity_str_check1)) {
  	    Log.d("MessengerActivity", "Successfully asked Boris for the password.");
			...
  	}
  	//第二个检测
  	if (mw_messengerAcitivty_EncodeInputText2(inputText.toString()).equals(this.mw_messengerActivity_str_check2)) {
  	    Log.d("MessengerActivity", "Successfully asked Boris nicely for the password.");
  	    ...
  	}
```

3.1 mw_messengerAcitivty_EncodeInputText1
高位^2, 低位^A , 然后反转字符数组. 反过来即可得到正确结果 : ==Boris, give me the password==
```java
 	private String mw_messengerActivity_str_check1 = "V@]EAASB\u0012WZF\u0012e,a$7(&am2(3.\u0003";
 
    private String mw_messengerAcitivty_EncodeInputText1(String str) {
        char[] charArray = str.toCharArray();
        for (int i = 0; i < charArray.length / 2; i++) {
            char c = charArray[i];
            charArray[i] = (char) (charArray[(charArray.length - i) - 1] ^ '2');
            charArray[(charArray.length - i) - 1] = (char) (c ^ 'A');
        }
        return new String(charArray);
    }
```

3.2 mw_messengerActivity_EncodeInputText2
- charArray[index]  = charArray[index] >> index % 8 ^ charArray[index]
- 反转数组
```java
	private String mw_messengerActivity_str_check2 = "\u0000dslp}oQ\u0000 dks$|M\u0000h +AYQg\u0000P*!M$gQ\u0000";
	
    private String mw_messengerActivity_EncodeInputText2(String str) {
        char[] charArray = str.toCharArray();
        for (int i = 0; i < charArray.length; i++) {
            charArray[i] = (char) ((charArray[i] >> (i % 8)) ^ charArray[i]);
        }
  
        for (int i2 = 0; i2 < charArray.length / 2; i2++) {
            char c = charArray[i2];
            charArray[i2] = charArray[(charArray.length - i2) - 1];
            charArray[(charArray.length - i2) - 1] = c;
        }
        return new String(charArray);
    }
```
- 反转数组
- 这时需要思考一下:  char_x >> index %8 ^ char_x = char_y
- char_y 和 index 己知. 只需要遍历一下char_x即可得到正确结果 : ==May I *PLEASE* have the password?==
- index % 8 时在8的整数倍时为0 . 此时 char xor char = 0, 所以会有空字符.
```java
    private static char GetChar(char ch, int shift) {
        for (char i = 0; i < 128; i++) {
            if ((i >> (shift % 8) ^ i) == ch)
                return i;
        }
        return 0;
    }

    private static String mw_messengerActivity_encode(String str) {
        char[] charArray = str.toCharArray();
        for (int i2 = 0; i2 < charArray.length / 2; i2++) {
            char c = charArray[i2];
            charArray[i2] = charArray[(charArray.length - i2) - 1];
            charArray[(charArray.length - i2) - 1] = c;
        }

        for (int i = 0; i < charArray.length; i++) {
            if ((char) charArray[i] == '\u0000') {
                charArray[i] = '?';
                continue;
            }
            charArray[i] = GetChar(charArray[i], i);
        }
        return new String(charArray);
    }
```
