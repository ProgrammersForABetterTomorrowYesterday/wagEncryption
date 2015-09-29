// Copyright (c) 2015, <your name>. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// TODO: Put public facing types in this file.

library WAGEncryption.base;
import "dart:typed_data" show Uint8List;
import "dart:io" show File, RandomAccessFile;
import 'package:bignum/bignum.dart';
import "package:cipher/cipher.dart";
import "package:cipher/impl/server.dart";
import "package:cipher/random/secure_random_base.dart" show SecureRandomBase;

export "dart:typed_data" show Uint8List;
export "package:cipher/cipher.dart" show AsymmetricKeyPair, RSAPublicKey, RSAPrivateKey;

/// Checks if you are awesome. Spoiler: you are.
class wagAESEncryption {
  Uint8List _key;
  KeyParameter _kparams;
  Uint8List iv;
  ParametersWithIV params;

  wagAESEncryption(String symkey, {String symiv: ""}) {
    _key = new Uint8List.fromList(symkey.codeUnits);
    _kparams = new KeyParameter( _key );
    if (symiv == "")
    {
      wagSecureRandom rand = new wagSecureRandom();
      iv = rand.nextBytes(16);
    } else {
      iv = new Uint8List.fromList(symiv.codeUnits);
    }
    params = new ParametersWithIV(_kparams, iv);
  }

  wagAESEncryption.fromUint8List(Uint8List symkey, [this.iv = null]) {
    _key = symkey;
    _kparams = new KeyParameter( _key );
    if (iv == null) {
      wagSecureRandom rand = new wagSecureRandom();
      iv = rand.nextBytes(16);
    }
    params = new ParametersWithIV(_kparams, iv);
  }

  String encrypt(String plaintext) {
    initCipher();
    var cipher = new BlockCipher( "AES/CBC" )
      ..init( true, params );

    var u8plainText = new Uint8List.fromList(plaintext.codeUnits);
    int fillrem = (u8plainText.lengthInBytes % 16);
    fillrem = 16 - fillrem;
    List tmplist = new List.from(u8plainText);
    for (int i = 0; i < fillrem; i++) {
      tmplist.add(0x00);
    }
    u8plainText = new Uint8List.fromList(tmplist);

    var tmp = new Uint8List.fromList(u8plainText);
    var maxlen = tmp.lengthInBytes;
    int rounds = (maxlen ~/ 16);
    int remainder = (maxlen % 16);

    int i = 0;
    while (i < rounds) {
      var len = cipher.processBlock( u8plainText, (16*i), tmp, (16*i) );
      i++;
    }

    return(new String.fromCharCodes(tmp));
  }

  String decrypt(String ciphertext) {
    initCipher();
    var cipher = new BlockCipher( "AES/CBC" )
      ..init( false, params );

    var u8cipherText = new Uint8List.fromList(ciphertext.codeUnits);

    var tmp = new Uint8List.fromList(u8cipherText);
    var maxlen = tmp.lengthInBytes;
    int rounds = (maxlen ~/ 16);
    int remainder = (maxlen % 16);

    int i = 0;
    while (i < rounds) {
      var len = cipher.processBlock( u8cipherText, (16*i), tmp, (16*i) );
      i++;
    }

    return(new String.fromCharCodes(tmp));
  }
}

class wagRSAEncryption {
  RSAPrivateKey priv = null;
  RSAPublicKey pub = null;

  wagRSAEncryption(RSAPublicKey this.pub, [RSAPrivateKey this.priv = null]);

  bool get hasPriv => ((priv != null) ? true : false);
  bool get hasPub => ((pub != null) ? true : false);
  bool get canEncrypt => hasPub;
  bool get canVerify => hasPub;
  bool get canDecrypt => hasPriv;
  bool get canSign => hasPriv;

  String encrypt(String plaintext) {
    if (!canEncrypt) {
      throw StateError;
    }

    initCipher();

    var pubpar = new PublicKeyParameter<RSAPublicKey>(pub);
    var cipher = new AsymmetricBlockCipher("RSA")
      ..init( true, pubpar )
    ;

    var cipherText = cipher.process(new Uint8List.fromList(plaintext.codeUnits));

    return(new String.fromCharCodes(cipherText));
  }

  String decrypt(String ciphertext) {
    if (!canDecrypt) {
      throw StateError;
    }

    initCipher();

    var privpar = new PrivateKeyParameter<RSAPrivateKey>(priv);
    var cipher = new AsymmetricBlockCipher("RSA")
      ..init(false, privpar)
    ;

    var plainText = cipher.process(new Uint8List.fromList(ciphertext.codeUnits));

    return(new String.fromCharCodes(plainText));
  }

  String sign(String message) {
    if (!canSign) {
      throw StateError;
    }

    initCipher();

    //TODO: Implement signing.
  }

  bool verify(String message, RSASignature signature) {
    if (!canSign) {
      throw StateError;
    }

    initCipher();

    //TODO: Implement signature verification.
  }
}

class wagSecureRandom extends SecureRandomBase {
  File urand;

  wagSecureRandom([String randFile = "/dev/urandom"]) {
    urand = new File(randFile);
  }

  Uint8List nextBytes(int bytes) {
    RandomAccessFile rand = urand.openSync();
    List<int> tmp  = new List.generate(bytes, (int index) {
      return rand.readByteSync();
    }, growable: false);
    rand.closeSync();
    return(new Uint8List.fromList(tmp));
  }

  int nextUint8() {
    return(nextBytes(1)[0]);
  }

  void seed(CipherParameters params) {
    return;
  }

  String get algorithmName {
    "wagSecureRandom";
  }
}

class wagKeyGen {
  static wagDerivedKey randomDerivedKey([int bytes = 32]) {
    String newpass = "";
    wagSecureRandom rand = new wagSecureRandom();

    newpass = new String.fromCharCodes(rand.nextBytes(bytes).toList());
    print("Password: $newpass");
    return deriveKey(newpass);
  }

  static wagDerivedKey deriveKey(String password, [var setSalt = null]) {
    initCipher();
    Uint8List salt = null;

    //If the provided salt is a string, make it a Uint8List
    if(setSalt is String) {
      setSalt = new Uint8List.fromList(setSalt.codeUnits);
    }
    //If the provided salt is now a Uint8List, move it into the salt.
    if(setSalt is Uint8List) {
      salt = setSalt;
    }
    //If the salt is still null, set a random salt.
    if(salt == null)
    {
      wagSecureRandom rand = new wagSecureRandom();
      salt = rand.nextBytes(4);
    }

    Pbkdf2Parameters params = new Pbkdf2Parameters(salt, 100, 16);
    KeyDerivator keyDerivator = new KeyDerivator("SHA-1/HMAC/PBKDF2")
      ..init(params);

    Uint8List passwordBytes = new Uint8List.fromList(password.codeUnits);

    Uint8List key = keyDerivator.process( passwordBytes );

    return(new wagDerivedKey()..dsalt = salt
                              ..dkey = key);
  }

  static AsymmetricKeyPair generateKeys() {
    initCipher();
    var rsapars = new RSAKeyGeneratorParameters(new BigInteger("65537"), 2048, 12);
    var params = new ParametersWithRandom(rsapars, new wagSecureRandom());

    var keyGenerator = new KeyGenerator("RSA")
      ..init(params);

    var keyPair = keyGenerator.generateKeyPair();

    return(keyPair);
  }
}

class wagDerivedKey {
  Uint8List dkey;
  Uint8List dsalt;

  encrypt(wagRSAEncryption cipher) {
    String s_dkey = new String.fromCharCodes(dkey.toList());
    String s_dsalt = new String.fromCharCodes(dsalt.toList());

    s_dkey = cipher.encrypt(s_dsalt);
    s_dsalt = cipher.encrypt(s_dkey);

    dkey = new Uint8List.fromList(s_dkey.codeUnits);
    dsalt = new Uint8List.fromList(s_dsalt.codeUnits);
  }

  decrypt(wagRSAEncryption cipher) {
    String s_dkey = new String.fromCharCodes(dkey.toList());
    String s_dsalt = new String.fromCharCodes(dsalt.toList());

    s_dkey = cipher.decrypt(s_dsalt);
    s_dsalt = cipher.decrypt(s_dkey);

    dkey = new Uint8List.fromList(s_dkey.codeUnits);
    dsalt = new Uint8List.fromList(s_dsalt.codeUnits);
  }
}