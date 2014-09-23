# android-secure-storage

Android library to securely store data on a device.

## Build Instructions

The project is built with maven so you just need to execute the command

'''bash
mvn clean install
'''

To build the jar and install it to your local repository.

## Including In Your Project

For maven you can add

'''xml
<dependency>
	<groupId>com.worldpay</groupId>
	<artifactId>secure-storage-android</artifactId>
	<version>1.0.1</version>
	<packaging>jar</packaging>
</dependency>
'''

For gradle you can add

'''groovy
compile 'com.worldpay:secure-storage-android:1.0.1:jar'
'''

Or in eclipse you can add it to your libs directory

## How To Use

1. Create a new instance of SecureStorage

'''java
SecureStorage secureStorage = new SecureStorage(context);
'''

2. Then either call encrypt or decrypt with the text you wish to encrypt/decrypt. This data is stored in SharedPreferences.

'''java
String encryptedText = secureStorage.encrypt("some text to encrypt");
String originalText = secureStorage.decrypt(encryptedText);
'''

3. If you need to clear the data stored on the device you need to call clearAll.

'''java
secureStorage.clearAll();
'''

