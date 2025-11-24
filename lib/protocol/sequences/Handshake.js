var Buffer          = require('safe-buffer').Buffer;
var Sequence        = require('./Sequence');
var Util            = require('util');
var Packets         = require('../packets');
var Auth            = require('../Auth');
var ClientConstants = require('../constants/client');
var Constants       = require('constants');

module.exports = Handshake;
Util.inherits(Handshake, Sequence);
function Handshake(options, callback) {
  Sequence.call(this, options, callback);

  options = options || {};

  this._config                        = options.config;
  this._handshakeInitializationPacket = null;
  this._waitingForServerPublicKey     = false;
  this._authSwitchScramble            = null;
}

Handshake.prototype.determinePacket = function determinePacket(firstByte, parser) {
  if (this._waitingForServerPublicKey) {
    this._waitingForServerPublicKey = false;
    return Packets.AuthMoreDataPacket;
  }

  if (firstByte === 0xff) {
    return Packets.ErrorPacket;
  }

  if (!this._handshakeInitializationPacket) {
    return Packets.HandshakeInitializationPacket;
  }

  if (firstByte === 0xfe) {
    return (parser.packetLength() === 1)
      ? Packets.UseOldPasswordPacket
      : Packets.AuthSwitchRequestPacket;
  }

  if (firstByte === 0x01) {
    var secondByte = parser.peak(1);

    if (secondByte === 0x03) {
      return Packets.FastAuthSuccessPacket;
    }

    if (secondByte === 0x04) {
      return Packets.PerformFullAuthenticationPacket;
    }
  }

  return undefined;
};

Handshake.prototype['AuthSwitchRequestPacket'] = function (packet) {
  var name = packet.authMethodName;

  // Store the auth switch scramble for later use (sha256_password needs this)
  this._authSwitchScramble = packet.authMethodData;

  var data = Auth.auth(name, packet.authMethodData, {
    password: this._config.password,
    ssl: this._config.ssl,
    socketPath: this._config.socketPath,
    secureAuth: this._config.secureAuth
  });

  if (data !== undefined) {
    // For sha256_password, check if requesting public key (indicated by 0x01 byte)
    if (name === 'sha256_password' && data.length === 1 && data[0] === 0x01) {
      this._waitingForServerPublicKey = true;
    }

    this.emit('packet', new Packets.AuthSwitchResponsePacket({
      data: data
    }));
  } else {
    var err   = new Error('MySQL is requesting the ' + name + ' authentication method, which is not supported.');
    err.code  = 'UNSUPPORTED_AUTH_METHOD';
    err.fatal = true;
    this.end(err);
  }
};

Handshake.prototype['HandshakeInitializationPacket'] = function(packet) {
  this._handshakeInitializationPacket = packet;

  this._config.protocol41 = packet.protocol41;

  if (this._config.compress && packet.hasCapabilityFlag(ClientConstants.CLIENT_COMPRESS)) {
    this._config.clientFlags |= ClientConstants.CLIENT_COMPRESS;
  }

  if (this._config.ssl) {
    if (!packet.hasCapabilityFlag(ClientConstants.CLIENT_SSL)) {
      var err = new Error('Server does not support secure connection');

      err.code = 'HANDSHAKE_NO_SSL_SUPPORT';
      err.fatal = true;

      this.end(err);
      return;
    }

    this._config.clientFlags |= ClientConstants.CLIENT_SSL;
    this.emit('packet', new Packets.SSLRequestPacket({
      clientFlags   : this._config.clientFlags,
      maxPacketSize : this._config.maxPacketSize,
      charsetNumber : this._config.charsetNumber
    }));
    this.emit('start-tls');
  } else {
    this._sendCredentials();
  }
};

Handshake.prototype._tlsUpgradeCompleteHandler = function() {
  this._sendCredentials();
};

Handshake.prototype._sendCredentials = function() {
  var packet = this._handshakeInitializationPacket;
  var scrambleBuff = null;

  if (packet.protocol41 && (packet.pluginData === 'caching_sha2_password' || packet.pluginData === 'sha256_password')) {
    scrambleBuff = Auth.auth(packet.pluginData, packet.scrambleBuff(), {
      password: this._config.password,
      ssl: this._config.ssl,
      socketPath: this._config.socketPath,
      secureAuth: this._config.secureAuth
    });

    if (scrambleBuff === undefined) {
      var err = new Error('Authentication requires secure connection');
      err.code = 'HANDSHAKE_SECURE_TRANSPORT_REQUIRED';
      err.fatal = true;
      this.end(err);
      return;
    }

    // For sha256_password, check if requesting public key (indicated by 0x01 byte)
    if (packet.pluginData === 'sha256_password' && scrambleBuff.length === 1 && scrambleBuff[0] === 0x01) {
      this._waitingForServerPublicKey = true;
    }
  } else if (packet.protocol41 && packet.pluginData === 'mysql_native_password') {
    scrambleBuff = Auth.token(this._config.password, packet.scrambleBuff());
  } else {
    scrambleBuff = Auth.scramble323(packet.scrambleBuff(), this._config.password);
  }

  this.emit('packet', new Packets.ClientAuthenticationPacket({
    clientFlags   : this._config.clientFlags,
    maxPacketSize : this._config.maxPacketSize,
    charsetNumber : this._config.charsetNumber,
    user          : this._config.user,
    database      : this._config.database,
    protocol41    : packet.protocol41,
    scrambleBuff  : scrambleBuff
  }));
};

Handshake.prototype['UseOldPasswordPacket'] = function() {
  if (!this._config.insecureAuth) {
    var err = new Error(
      'MySQL server is requesting the old and insecure pre-4.1 auth mechanism. ' +
      'Upgrade the user password or use the {insecureAuth: true} option.'
    );

    err.code = 'HANDSHAKE_INSECURE_AUTH';
    err.fatal = true;

    this.end(err);
    return;
  }

  this.emit('packet', new Packets.OldPasswordPacket({
    scrambleBuff: Auth.scramble323(this._handshakeInitializationPacket.scrambleBuff(), this._config.password)
  }));
};

Handshake.prototype['FastAuthSuccessPacket'] = function() {
  // Just to signal an upcoming OkPacket
};

Handshake.prototype['PerformFullAuthenticationPacket'] = function() {
  var password = this._config.password;

  if (this._config.ssl || this._config.socketPath) {
    // The connection is encrypted or a local socket, so the password can be sent in plaintext
    this.emit('packet', new Packets.ClearTextPasswordPacket({
      data: password
    }));
    return;
  }

  var secureAuth = this._config.secureAuth;

  if (secureAuth) {
    if (secureAuth === true || secureAuth.key === undefined) {
      // Fetch the authentication RSA public key from the server
      this._waitingForServerPublicKey = true;
      this.emit('packet', new Packets.HandshakeResponse41Packet());
      return;
    }

    if (typeof secureAuth.key === 'string') {
      // Use the provided authentication RSA public key
      this.AuthMoreDataPacket({ data: secureAuth.key });
      return;
    }
  }

  var err = new Error('Authentication requires secure connection');
  err.code = 'HANDSHAKE_SECURE_TRANSPORT_REQUIRED';
  err.fatal = true;

  this.end(err);
};

Handshake.prototype['AuthMoreDataPacket'] = function(packet) {
  var secureAuth = {
    key     : packet.data,
    padding : this._config.secureAuth.padding || Constants.RSA_PKCS1_OAEP_PADDING
  };

  try {
    // Use the auth switch scramble if available (for sha256_password), otherwise use handshake scramble
    var scramble = this._authSwitchScramble || this._handshakeInitializationPacket.scrambleBuff();
    var password = Auth.encrypt(this._config.password, scramble, secureAuth);

    this.emit('packet', new Packets.AuthSwitchResponsePacket({
      data: password
    }));
  } catch (err) {
    if (err.code !== 'PUB_KEY_ENCRYPTION_NOT_AVAILABLE') {
      throw err;
    }

    var error = new Error('Authentication requires secure connection');
    error.code = 'HANDSHAKE_SECURE_TRANSPORT_REQUIRED';
    error.fatal = true;

    this.end(error);
  }
};

Handshake.prototype['ErrorPacket'] = function(packet) {
  var err = this._packetToError(packet, true);
  err.fatal = true;
  this.end(err);
};
