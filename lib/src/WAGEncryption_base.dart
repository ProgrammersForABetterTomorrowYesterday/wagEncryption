// Copyright (c) 2015, <your name>. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

// TODO: Put public facing types in this file.

library WAGEncryption.base;
import "dart:typed_data" show Uint8List;
import "dart:io" show File, RandomAccessFile;
import 'dart:convert';
import 'package:bignum/bignum.dart';
import "package:cipher/cipher.dart";
import "package:cipher/impl/server.dart";
import "package:cipher/random/secure_random_base.dart" show SecureRandomBase;
import "package:rsa_pkcs/rsa_pkcs.dart" as Parser show RSAPKCSParser, RSAKeyPair, RSAPublicKey, RSAPrivateKey;

export "dart:typed_data" show Uint8List;
export "package:cipher/cipher.dart" show AsymmetricKeyPair, RSAPublicKey, RSAPrivateKey, RSASignature;

abstract class wagEncryption {
  String encrypt(String plaintext);
  String decrypt(String ciphertext);
}

class wagMessageEncryption implements wagEncryption {
  wagAESEncryption rand_aes;
  wagRSAEncryption host_rsa;
  wagRSAEncryption recip_rsa;
  bool used = false;

  wagMessageEncryption(wagRSAEncryption this.host_rsa, wagRSAEncryption this.recip_rsa);

  String encrypt(String plaintext) {
    if(!host_rsa.canSign || !recip_rsa.canEncrypt)
      throw new UnsupportedError("Current encrypted object is unable to sign and encrypt messages.");
    if (!used) {
      used = true;

      //Get host sig on pt
      RSASignature tmpsig = host_rsa.sign(plaintext);
      //Convert RSASignature to String
      Uint8List sigbytes = tmpsig.bytes;
      String sig = wagConvert.u8L_string(sigbytes);
      //Concatenate sig and pt
      StringBuffer signedbuff = new StringBuffer();
      signedbuff.writeAll([sig, plaintext], "|_|");

      //Generate a new random AESKey
      wagDerivedKey randAESKey = wagKeyGen.randomDerivedKey();
      rand_aes = new wagAESEncryption.fromUint8List(randAESKey.dk_key, randAESKey.dk_iv);
      //Encrypt the signed plaintext with the new AESKey
      String ciphertext = rand_aes.encrypt(signedbuff.toString());
      //Convert the AESKey object into a String, and encrypt it with recip_rsa
      String pt_aesKey = rand_aes.serializeKey();
      String ct_aesKey = recip_rsa.encrypt(pt_aesKey);
      //Concatenate the encrypted AESKey and the encrypted (signed) message
      StringBuffer tmpbuf = new StringBuffer();
      tmpbuf.writeAll([ct_aesKey, ciphertext], "|_|");
      return tmpbuf.toString();
    }
    throw new StateError("Encryption object expired, may not encrypt multiple times with the same object.");
  }

  String decrypt(String ciphertext) {
    if(!host_rsa.canVerify || !recip_rsa.canDecrypt)
      throw new UnsupportedError("Current encrypted object is unable to decrypt and verify messages.");
    if (!used) {
      used = true;
      var split_ct = ciphertext.split("|_|");
      String aesKey = recip_rsa.decrypt(split_ct[0]);
      String message_ct = split_ct[1];
      rand_aes = new wagAESEncryption.deserialize(aesKey);
      String signedmessage_pt = rand_aes.decrypt(message_ct);
      var splitmessage_pt = signedmessage_pt.split("|_|");
      String message_sig = splitmessage_pt[0];
      String message_pt = splitmessage_pt[1];
      RSASignature sig = new RSASignature(wagConvert.string_u8l(message_sig));
      bool verified = host_rsa.verify(message_pt, sig);
      if (verified) {
        return message_pt;
      }
      throw new ArgumentError("Unverified: $message_pt");

    }
    throw new StateError("Encryption object expired, may not decrypt multiple times with the same object.");
  }
}

class wagAESEncryption implements wagEncryption {
  Uint8List _key;
  KeyParameter _kparams;
  Uint8List iv;
  ParametersWithIV params;

  wagAESEncryption(String symkey, {String symiv: ""}) {
    _key = wagConvert.string_u8l(symkey);
    _kparams = new KeyParameter( _key );
    if (symiv == "")
    {
      wagSecureRandom rand = new wagSecureRandom();
      iv = rand.nextBytes(16);
    } else {
      iv = wagConvert.string_u8l(symiv);
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

  wagAESEncryption.deserialize(String kI) {
    var key = kI.split("|_|");
    String k = key[0];
    String iv = key[1];

    this._key = wagConvert.string_u8l(k);
    this._kparams = new KeyParameter(_key);
    this.iv = wagConvert.string_u8l(iv);
    this.params = new ParametersWithIV(this._kparams, this.iv);
  }

  String serializeKey() {
    String k = wagConvert.u8L_string(_key);
    String i = wagConvert.u8L_string(iv);
    return "$k|_|$i";
  }

  String encrypt(String plaintext) {
    initCipher();
    var cipher = new BlockCipher( "AES/CBC" )
      ..init( true, params );

    var u8plainText = wagConvert.string_u8l(plaintext);
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
      cipher.processBlock( u8plainText, (16*i), tmp, (16*i) );
      i++;
    }

    if(remainder != 0) {
      cipher.processBlock(u8plainText, ((16*i) + remainder), tmp, ((16*i) + remainder));
    }

    return(wagConvert.u8L_string(tmp));
  }

  String decrypt(String ciphertext) {
    initCipher();
    var cipher = new BlockCipher( "AES/CBC" )
      ..init( false, params );

    var u8cipherText = wagConvert.string_u8l(ciphertext);

    var tmp = new Uint8List.fromList(u8cipherText);
    var maxlen = tmp.lengthInBytes;
    int rounds = (maxlen ~/ 16);
    int remainder = (maxlen % 16);

    int i = 0;
    while (i < rounds) {
      cipher.processBlock( u8cipherText, (16*i), tmp, (16*i) );
      i++;
    }

    if(remainder != 0) {
      cipher.processBlock(u8cipherText, ((16*i) + remainder), tmp, ((16*i) + remainder));
    }

    return(wagConvert.u8L_string(tmp));
  }
}

class wagRSAEncryption implements wagEncryption {
  RSAPrivateKey priv = null;
  RSAPublicKey pub = null;

  wagRSAEncryption(RSAPublicKey this.pub, [RSAPrivateKey this.priv = null]);
  wagRSAEncryption.deserialize(String json) {
    Map<String, List<int>> cereal = JSON.decode(json);
    RSAPublicKey public = null;
    RSAPrivateKey private = null;

    BigInteger modulus = new BigInteger(cereal['modulus'], 16);
    BigInteger publicExponent = new BigInteger(cereal['publicexponent'], 16);

    if(cereal['p'] != null) {
      BigInteger p = new BigInteger(cereal['p'], 16);
      BigInteger q = new BigInteger(cereal['q'], 16);
      BigInteger privateExponent = new BigInteger(cereal['privateexponent'], 16);
      private = new RSAPrivateKey(modulus, privateExponent, p, q);
    }
    public = new RSAPublicKey(modulus, publicExponent);

    this.pub = public;
    this.priv = private;
  }

  String serializeKeys() {
    Map<String, String> cereal = new Map<String, String>();
    if(priv == null) {
      cereal['p'] = null;
      cereal['q'] = null;
      cereal['privateexponent'] = null;
    } else {
      cereal['p'] = priv.p.toString(16);
      cereal['q'] = priv.q.toString(16);
      cereal['privateexponent'] = priv.exponent.toString(16);
    }
    cereal['modulus'] = pub.modulus.toString(16);
    cereal['publicexponent'] = pub.exponent.toString(16);
    return JSON.encode(cereal);
  }

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

    var cipherText = cipher.process(wagConvert.string_u8l(plaintext));

    return(wagConvert.u8L_string(cipherText));
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

    var plainText = cipher.process(wagConvert.string_u8l(ciphertext));

    return(wagConvert.u8L_string(plainText));
  }
  //TODO: Figure out why the sig is not working. :-(
  RSASignature sign(String message) {
    if (!canSign) {
      throw StateError;
    }

    initCipher();

    var privParams = new PrivateKeyParameter(priv);
    var signParams = new ParametersWithRandom(privParams, new wagSecureRandom());

    Signer signer = new Signer("SHA-1/RSA")
      ..init( true, signParams )
    ;

    return signer.generateSignature(wagConvert.string_u8l(message));
  }

  bool verify(String message, RSASignature signature) {
    if (!canVerify) {
      throw StateError;
    }

    initCipher();

    var verifyParams = new PublicKeyParameter(pub);
    var randParams = new ParametersWithRandom(verifyParams, new wagSecureRandom());

    Signer signer = new Signer("SHA-1/RSA")
      ..init( false, randParams )
    ;

    bool verified;
    try {
      verified = signer.verifySignature(wagConvert.string_u8l(message), signature);
    } catch(e) {
      verified = false;
    }

    return verified;
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
  static wagDerivedKey randomDerivedKey([int bytes = 16]) {
    String newpass = "";
    wagSecureRandom rand = new wagSecureRandom();

    newpass = wagConvert.u8L_string(rand.nextBytes(bytes));
    return deriveKey(newpass);
  }

  static wagDerivedKey deriveKey(String password, [var setSalt = null]) {
    initCipher();
    Uint8List salt = null;

    //If the provided salt is a string, make it a Uint8List
    if(setSalt is String) {
      setSalt = wagConvert.string_u8l(setSalt);
    }
    //If the provided salt is now a Uint8List, move it into the salt.
    if(setSalt is Uint8List) {
      salt = setSalt;
    }
    //If the salt is still null, set a random salt.
    if(salt == null)
    {
      wagSecureRandom rand = new wagSecureRandom();
      salt = rand.nextBytes(16);
    }

    Pbkdf2Parameters params = new Pbkdf2Parameters(salt, 100, 16);
    KeyDerivator keyDerivator = new KeyDerivator("SHA-1/HMAC/PBKDF2")
      ..init(params);

    Uint8List passwordBytes = wagConvert.string_u8l(password);

    Uint8List key = keyDerivator.process( passwordBytes );

    return(new wagDerivedKey()..dk_iv = salt
                              ..dk_key = key);
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
  Uint8List dk_key;
  Uint8List dk_iv;

  void encrypt(wagEncryption cipher) {
    String s_dkey = wagConvert.u8L_string(dk_key);
    s_dkey = cipher.encrypt(s_dkey);
    dk_key = wagConvert.string_u8l(s_dkey);
  }

  void decrypt(wagEncryption cipher) {
    String s_dkey = wagConvert.u8L_string(dk_key);
    s_dkey = cipher.decrypt(s_dkey);
    dk_key = wagConvert.string_u8l(s_dkey);
  }
}

class wagConvert {
  static String u8L_string(Uint8List bytelist) {
    return new String.fromCharCodes(bytelist.toList());
  }

  static Uint8List string_u8l(String message) {
    return new Uint8List.fromList(message.codeUnits);
  }

  static AsymmetricKeyPair parsePemString(String pem) {
    Parser.RSAPKCSParser parser = new Parser.RSAPKCSParser();
    Parser.RSAKeyPair pair = parser.parsePEM(pem);
    Parser.RSAPublicKey pub = pair.public;
    Parser.RSAPrivateKey priv = pair.private;

    //TODO: Implement conversion between strings representing PEM files and Cipher.AsymmetricKeyPair
  }
}