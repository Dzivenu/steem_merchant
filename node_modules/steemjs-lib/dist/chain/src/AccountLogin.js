"use strict";

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var PrivateKey = require("../../ecc/src/PrivateKey");
var key = require("../../ecc/src/KeyUtils");

var KeyCache = function () {
    function KeyCache() {
        _classCallCheck(this, KeyCache);

        this._keyCachePriv = new Map();
        this._keyCachePub = new Map();
        this._myKeys = new Map();
    }

    _createClass(KeyCache, [{
        key: "setPrivKey",
        value: function setPrivKey(key, privKey) {
            this._keyCachePriv.set(key, privKey);
        }
    }, {
        key: "hasPrivKey",
        value: function hasPrivKey(key) {
            return this._keyCachePriv.has(key);
        }
    }, {
        key: "getPrivKey",
        value: function getPrivKey(key) {
            return this._keyCachePriv.get(key);
        }
    }, {
        key: "setPubKey",
        value: function setPubKey(key, pubKey) {
            this._keyCachePub.set(key, pubKey);
        }
    }, {
        key: "hasPubKey",
        value: function hasPubKey(key) {
            return this._keyCachePub.has(key);
        }
    }, {
        key: "getPubKey",
        value: function getPubKey(key) {
            return this._keyCachePub.get(key);;
        }
    }, {
        key: "setMyKey",
        value: function setMyKey(key, privKey) {
            this._myKeys.set(key, privKey);
        }
    }, {
        key: "getMyKey",
        value: function getMyKey(key) {
            return this._myKeys.get(key);
        }
    }]);

    return KeyCache;
}();

var AccountLogin = function () {
    function AccountLogin() {
        _classCallCheck(this, AccountLogin);

        this.reset();
        this.keyCache = new KeyCache();
    }

    _createClass(AccountLogin, [{
        key: "reset",
        value: function reset() {
            this.state = { loggedIn: false, roles: ["active", "owner", "posting", "memo"] };

            this.subs = {};
        }
    }, {
        key: "addSubscription",
        value: function addSubscription(cb) {
            this.subs[cb] = cb;
        }
    }, {
        key: "setRoles",
        value: function setRoles(roles) {
            this.state.roles = roles;
        }
    }, {
        key: "getRoles",
        value: function getRoles() {
            return this.state.roles;
        }
    }, {
        key: "generateKeys",
        value: function generateKeys(accountName, password, roles, prefix) {
            var _this = this;

            if (!accountName || !password) {
                throw new Error("Account name or password required");
            }
            if (password.length < 12) {
                throw new Error("Password must have at least 12 characters");
            }

            var privKeys = {};
            var pubKeys = {};

            (roles || this.state.roles).forEach(function (role) {
                var seed = accountName + role + password;
                var pkey = _this.keyCache.hasPrivKey(role) ? _this.keyCache.getPrivKey(role) : PrivateKey.fromSeed(key.normalize_brainKey(seed));
                _this.keyCache.setPrivKey(role, pkey);

                privKeys[role] = pkey;
                pubKeys[role] = _this.keyCache.getPubKey(role) ? _this.keyCache.getPubKey(role) : pkey.toPublicKey().toString(prefix);

                _this.keyCache.setPubKey(role, pubKeys[role]);
            });

            return { privKeys: privKeys, pubKeys: pubKeys };
        }
    }, {
        key: "fromPrivKey",
        value: function fromPrivKey(accountName, privateKey, roles, prefix) {
            var _this2 = this;

            if (!privateKey) {
                return null;
            }
            var privKeys = {};
            var pubKeys = {};

            (roles || this.state.roles).forEach(function (role) {

                var pkey = _this2.keyCache.hasPrivKey(role) ? _this2.keyCache.getPrivKey(role) : PrivateKey.fromWif(privateKey);
                _this2.keyCache.setPrivKey(role, pkey);

                privKeys[role] = pkey;
                pubKeys[role] = _this2.keyCache.getPubKey(role) ? _this2.keyCache.getPubKey(role) : pkey.toPublicKey().toString(prefix);

                _this2.keyCache.setPubKey(role, pubKeys[role]);
            });

            return { privKeys: privKeys, pubKeys: pubKeys };
        }
    }, {
        key: "getPubKeys",
        value: function getPubKeys() {
            var _this3 = this;

            return this.state.roles.map(function (role) {
                return _this3.keyCache.getPubKey(role);
            });
        }
    }, {
        key: "checkKeys",
        value: function checkKeys(_ref) {
            var _this4 = this;

            var accountName = _ref.accountName;
            var password = _ref.password;
            var auths = _ref.auths;
            var _ref$privateKey = _ref.privateKey;
            var privateKey = _ref$privateKey === undefined ? null : _ref$privateKey;

            if (!accountName || !password && !privateKey || !auths) {
                throw new Error("checkKeys: Missing inputs");
            }
            var hasKey = false;

            var _loop = function _loop(role) {
                var keys = void 0;
                if (password) {
                    keys = _this4.generateKeys(accountName, password, [role]);
                } else if (privateKey) {
                    keys = _this4.fromPrivKey(accountName, privateKey, [role]);
                }

                if (keys && Object.keys(keys).length) {
                    (function () {
                        var _keys = keys;
                        var privKeys = _keys.privKeys;
                        var pubKeys = _keys.pubKeys;

                        auths[role].forEach(function (key) {
                            if (key[0] === pubKeys[role]) {
                                hasKey = true;
                                _this4.keyCache.setMyKey(role, { priv: privKeys[role], pub: pubKeys[role] });
                            }
                        });
                    })();
                }
            };

            for (var role in auths) {
                _loop(role);
            };

            if (hasKey) {
                this.name = accountName;
            }

            this.state.loggedIn = hasKey;

            return hasKey;
        }
    }, {
        key: "signTransaction",
        value: function signTransaction(tr) {
            var _this5 = this;

            var signerPubkeys = arguments.length <= 1 || arguments[1] === undefined ? {} : arguments[1];
            var requiredPubkeys = arguments[2];


            var myKeys = {};
            var hasKey = false;

            this.state.roles.forEach(function (role) {
                var myKey = _this5.keyCache.getMyKey(role);
                if (myKey) {
                    if (signerPubkeys[myKey.pub]) {
                        hasKey = true;
                        return;
                    }
                    hasKey = true;
                    signerPubkeys[myKey.pub] = true;
                    if (requiredPubkeys && requiredPubkeys.indexOf(myKey.pub) !== -1) {
                        tr.add_signer(myKey.priv, myKey.pub);
                    } else if (!requiredPubkeys) {
                        tr.add_signer(myKey.priv, myKey.pub);
                    }
                }
            });

            if (!hasKey) {
                console.error("You do not have any private keys to sign this transaction");
                throw new Error("You do not have any private keys to sign this transaction");
            }
        }
    }]);

    return AccountLogin;
}();

module.exports = AccountLogin;