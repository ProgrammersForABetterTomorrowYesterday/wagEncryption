// Copyright (c) 2015, <your name>. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

library WAGEncryption.example;

import 'package:WAGEncryption/WAGEncryption.dart';

main() {

  AsymmetricKeyPair pair = wagKeyGen.generateKeys();
  RSAPublicKey pub = pair.publicKey;
  RSAPrivateKey priv = pair.privateKey;
  wagRSAEncryption cipher = new wagRSAEncryption(pub, priv);

  String pt = "This is a test.";
  RSASignature sig = cipher.sign(pt);
  print("PT: $pt");
  print("Verified: ${cipher.verify(pt, sig)}");
  print("Not Verified: ${cipher.verify("This is different text.", sig)}");

  pair = wagKeyGen.generateKeys();
  wagRSAEncryption cipher2 = new wagRSAEncryption(pair.publicKey, pair.privateKey);
  print("Not Verified: ${cipher2.verify(pt, sig)}");
  print("Not Verified: ${cipher2.verify("This is different text.", sig)}");

  /*wagDerivedKey key = wagKeyGen.randomDerivedKey();
  wagAESEncryption cipher = new wagAESEncryption.fromUint8List(key.dkey, key.dsalt);
  print(key.dsalt.toList());
  String pt = "Test";
  String ct = cipher.encrypt(pt);
  print(pt);
  print(ct);
  print(cipher.decrypt(ct))*/;

  /*AsymmetricKeyPair pair = wagKeyGen.generateKeys();
  RSAPublicKey pub = pair.publicKey;
  RSAPrivateKey priv = pair.privateKey;

  wagDerivedKey AESKey = wagKeyGen.randomDerivedKey();
  print("Key: ${AESKey.dk_key}");
  print("Salt: ${AESKey.dk_iv}");

  wagRSAEncryption RSAcipher = new wagRSAEncryption(pub, priv);
  wagAESEncryption AEScipher = new wagAESEncryption.fromUint8List(AESKey.dk_key, AESKey.dk_iv);

  AESKey.encrypt(RSAcipher);
  print("Encrypted.");
  print("Key: ${AESKey.dk_key}");
  print("Salt: ${AESKey.dk_iv}");

  String pt = "This is plaintext!";
  print("PT: $pt");
  String ct = AEScipher.encrypt(pt);
  print("CT: $ct");

  AESKey.decrypt(RSAcipher);
  wagAESEncryption AESdecipher = new wagAESEncryption.fromUint8List(AESKey.dk_key, AESKey.dk_iv);
  pt = "";
  pt = AESdecipher.decrypt(ct);
  print("Decrypted.");
  print("Key: ${AESKey.dk_key}");
  print("Salt: ${AESKey.dk_iv}");
  print("PT: ${AESdecipher.decrypt(ct)}");*/

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
