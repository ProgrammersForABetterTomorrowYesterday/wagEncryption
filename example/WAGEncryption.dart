// Copyright (c) 2015, <your name>. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

library WAGEncryption.example;

import 'package:WAGEncryption/WAGEncryption.dart';

main() {


  wagAESEncryption cipher = new wagAESEncryption.fromUint8List()

  /*AsymmetricKeyPair pair = wagKeyGen.generateKeys();
  RSAPublicKey pub = pair.publicKey;
  RSAPrivateKey priv = pair.privateKey;

  wagDerivedKey AESKey = wagKeyGen.randomDerivedKey();
  print("Key: ${AESKey.dkey}");
  print("Salt: ${AESKey.dsalt}");

  wagRSAEncryption RSAcipher = new wagRSAEncryption(pub, priv);
  wagAESEncryption AEScipher = new wagAESEncryption.fromUint8List(AESKey.dkey, AESKey.dsalt);

  AESKey.encrypt(RSAcipher);
  print("Encrypted.");
  print("Key: ${AESKey.dkey}");
  print("Salt: ${AESKey.dsalt}");

  String pt = "This is plaintext!";
  print("PT: $pt");
  //VVVV FAILS VVVV
  //String ct = AEScipher.encrypt(pt);
  //^^^^ FAILS ^^^^
  //print("CT: $ct");

  AESKey.decrypt(RSAcipher);
  //wagAESEncryption AESdecipher = new wagAESEncryption.fromUint8List(AESKey.dkey, AESKey.dsalt);
  pt = "";
  //pt = AESdecipher.decrypt(ct);
  print("Decrypted.");
  print("Key: ${AESKey.dkey}");
  print("Salt: ${AESKey.dsalt}");*/

  /*wagDerivedKey key = wagKeyGen.deriveKey("Password");
  print("Salt: ${key.dsalt}");
  print("Key: ${key.dkey}");
  key = wagKeyGen.deriveKey("Password");
  print("Salt: ${key.dsalt}");
  print("Key: ${key.dkey}");
  key = wagKeyGen.deriveKey("Another");
  print("Salt: ${key.dsalt}");
  print("Key: ${key.dkey}");*/
  /*wagSecureRandom rand = new wagSecureRandom();
  Uint8List tmp0 = rand.nextBytes(16);
  print("Round 1:");
  print(tmp0);
  Uint8List tmp2 = rand.nextBytes(32);
  print("Round 2:");
  print(tmp2.toString());
  Uint8List tmp3 = rand.nextBytes(16);
  print("Round 3:");
  print(tmp3.toString());

*/
  /*wagSecureRandom rand = new wagSecureRandom();
  String AESKey1 = "fHøå©ªHüD—ì%©È\"â_)Ê³©”,Î";
  String AESKey2 = "€5¿w?¹šÿÞd‘_xyóÓ\$j«Y";
  Uint8List AESKey3 = rand.nextBytes(24);
  print("AES Key 1");
  wagAESEncryption tmp = new wagAESEncryption(AESKey1);
  var cip = tmp.encrypt("This is a string of characters");
  print("Encrypted: $cip");
  cip = tmp.decrypt(cip);
  print("Decrypted: $cip");
  cip = "";

  print("AES Key 2");
  tmp = new wagAESEncryption(AESKey2);
  cip = tmp.encrypt("This is another string of characters");
  print("Encrypted: $cip");
  cip = tmp.decrypt(cip);
  print("Decrypted: $cip");
  cip = "";

  print("AES Key 3");
  tmp = new wagAESEncryption.fromUint8List(AESKey3);
  var tmp123456 = new wagAESEncryption.fromUint8List(AESKey3, tmp.iv);
  cip = tmp.encrypt("How many characters do you need to make a string?");
  print("Encrypted: $cip");
  cip = tmp.decrypt(cip);
  print("Decrypted: $cip");
  cip = "";*/
}
