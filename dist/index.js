// @bun
var __create = Object.create
var __defProp = Object.defineProperty
var __getProtoOf = Object.getPrototypeOf
var __getOwnPropNames = Object.getOwnPropertyNames
var __hasOwnProp = Object.prototype.hasOwnProperty
var __toESM = (mod, isNodeMode, target) => {
    target = mod != null ? __create(__getProtoOf(mod)) : {}
    const to =
        isNodeMode || !mod || !mod.__esModule
            ? __defProp(target, 'default', { value: mod, enumerable: true })
            : target
    for (const key of __getOwnPropNames(mod))
        if (!__hasOwnProp.call(to, key))
            __defProp(to, key, {
                get: () => mod[key],
                enumerable: true,
            })
    return to
}
var __commonJS = (cb, mod) => () => (mod || cb((mod = { exports: {} }).exports, mod), mod.exports)

// node_modules/@actions/core/lib/utils.js
var require_utils = __commonJS((exports) => {
    var toCommandValue = (input) => {
        if (input === null || input === undefined) {
            return ''
        } else if (typeof input === 'string' || input instanceof String) {
            return input
        }
        return JSON.stringify(input)
    }
    var toCommandProperties = (annotationProperties) => {
        if (!Object.keys(annotationProperties).length) {
            return {}
        }
        return {
            title: annotationProperties.title,
            file: annotationProperties.file,
            line: annotationProperties.startLine,
            endLine: annotationProperties.endLine,
            col: annotationProperties.startColumn,
            endColumn: annotationProperties.endColumn,
        }
    }
    Object.defineProperty(exports, '__esModule', { value: true })
    exports.toCommandProperties = exports.toCommandValue = undefined
    exports.toCommandValue = toCommandValue
    exports.toCommandProperties = toCommandProperties
})

// node_modules/@actions/core/lib/command.js
var require_command = __commonJS((exports) => {
    var issueCommand = (command, properties, message) => {
        const cmd = new Command(command, properties, message)
        process.stdout.write(cmd.toString() + os.EOL)
    }
    var issue = (name, message = '') => {
        issueCommand(name, {}, message)
    }
    var escapeData = (s) =>
        utils_1.toCommandValue(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A')
    var escapeProperty = (s) =>
        utils_1
            .toCommandValue(s)
            .replace(/%/g, '%25')
            .replace(/\r/g, '%0D')
            .replace(/\n/g, '%0A')
            .replace(/:/g, '%3A')
            .replace(/,/g, '%2C')
    var __createBinding =
        (exports && exports.__createBinding) ||
        (Object.create
            ? (o, m, k, k2) => {
                  if (k2 === undefined) k2 = k
                  Object.defineProperty(o, k2, { enumerable: true, get: () => m[k] })
              }
            : (o, m, k, k2) => {
                  if (k2 === undefined) k2 = k
                  o[k2] = m[k]
              })
    var __setModuleDefault =
        (exports && exports.__setModuleDefault) ||
        (Object.create
            ? (o, v) => {
                  Object.defineProperty(o, 'default', { enumerable: true, value: v })
              }
            : (o, v) => {
                  o['default'] = v
              })
    var __importStar =
        (exports && exports.__importStar) ||
        ((mod) => {
            if (mod && mod.__esModule) return mod
            var result = {}
            if (mod != null) {
                for (var k in mod)
                    if (k !== 'default' && Object.hasOwnProperty.call(mod, k))
                        __createBinding(result, mod, k)
            }
            __setModuleDefault(result, mod)
            return result
        })
    Object.defineProperty(exports, '__esModule', { value: true })
    exports.issue = exports.issueCommand = undefined
    var os = __importStar(import.meta.require('os'))
    var utils_1 = require_utils()
    exports.issueCommand = issueCommand
    exports.issue = issue
    var CMD_STRING = '::'

    class Command {
        constructor(command, properties, message) {
            if (!command) {
                command = 'missing.command'
            }
            this.command = command
            this.properties = properties
            this.message = message
        }
        toString() {
            let cmdStr = CMD_STRING + this.command
            if (this.properties && Object.keys(this.properties).length > 0) {
                cmdStr += ' '
                let first = true
                for (const key in this.properties) {
                    if (this.properties.hasOwnProperty(key)) {
                        const val = this.properties[key]
                        if (val) {
                            if (first) {
                                first = false
                            } else {
                                cmdStr += ','
                            }
                            cmdStr += `${key}=${escapeProperty(val)}`
                        }
                    }
                }
            }
            cmdStr += `${CMD_STRING}${escapeData(this.message)}`
            return cmdStr
        }
    }
})

// node_modules/uuid/dist/rng.js
var require_rng = __commonJS((exports) => {
    var _interopRequireDefault = (obj) => (obj && obj.__esModule ? obj : { default: obj })
    var rng = () => {
        if (poolPtr > rnds8Pool.length - 16) {
            _crypto.default.randomFillSync(rnds8Pool)
            poolPtr = 0
        }
        return rnds8Pool.slice(poolPtr, (poolPtr += 16))
    }
    Object.defineProperty(exports, '__esModule', {
        value: true,
    })
    exports.default = rng
    var _crypto = _interopRequireDefault(import.meta.require('crypto'))
    var rnds8Pool = new Uint8Array(256)
    var poolPtr = rnds8Pool.length
})

// node_modules/uuid/dist/regex.js
var require_regex = __commonJS((exports) => {
    Object.defineProperty(exports, '__esModule', {
        value: true,
    })
    exports.default = undefined
    var _default =
        /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000)$/i
    exports.default = _default
})

// node_modules/uuid/dist/validate.js
var require_validate = __commonJS((exports) => {
    var _interopRequireDefault = (obj) => (obj && obj.__esModule ? obj : { default: obj })
    var validate = (uuid) => typeof uuid === 'string' && _regex.default.test(uuid)
    Object.defineProperty(exports, '__esModule', {
        value: true,
    })
    exports.default = undefined
    var _regex = _interopRequireDefault(require_regex())
    var _default = validate
    exports.default = _default
})

// node_modules/uuid/dist/stringify.js
var require_stringify = __commonJS((exports) => {
    var _interopRequireDefault = (obj) => (obj && obj.__esModule ? obj : { default: obj })
    var stringify = (arr, offset = 0) => {
        const uuid = (
            byteToHex[arr[offset + 0]] +
            byteToHex[arr[offset + 1]] +
            byteToHex[arr[offset + 2]] +
            byteToHex[arr[offset + 3]] +
            '-' +
            byteToHex[arr[offset + 4]] +
            byteToHex[arr[offset + 5]] +
            '-' +
            byteToHex[arr[offset + 6]] +
            byteToHex[arr[offset + 7]] +
            '-' +
            byteToHex[arr[offset + 8]] +
            byteToHex[arr[offset + 9]] +
            '-' +
            byteToHex[arr[offset + 10]] +
            byteToHex[arr[offset + 11]] +
            byteToHex[arr[offset + 12]] +
            byteToHex[arr[offset + 13]] +
            byteToHex[arr[offset + 14]] +
            byteToHex[arr[offset + 15]]
        ).toLowerCase()
        if (!(0, _validate.default)(uuid)) {
            throw TypeError('Stringified UUID is invalid')
        }
        return uuid
    }
    Object.defineProperty(exports, '__esModule', {
        value: true,
    })
    exports.default = undefined
    var _validate = _interopRequireDefault(require_validate())
    var byteToHex = []
    for (let i = 0; i < 256; ++i) {
        byteToHex.push((i + 256).toString(16).substr(1))
    }
    var _default = stringify
    exports.default = _default
})

// node_modules/uuid/dist/v1.js
var require_v1 = __commonJS((exports) => {
    var _interopRequireDefault = (obj) => (obj && obj.__esModule ? obj : { default: obj })
    var v1 = (options, buf, offset) => {
        let i = (buf && offset) || 0
        const b = buf || new Array(16)
        options = options || {}
        let node = options.node || _nodeId
        let clockseq = options.clockseq !== undefined ? options.clockseq : _clockseq
        if (node == null || clockseq == null) {
            const seedBytes = options.random || (options.rng || _rng.default)()
            if (node == null) {
                node = _nodeId = [
                    seedBytes[0] | 1,
                    seedBytes[1],
                    seedBytes[2],
                    seedBytes[3],
                    seedBytes[4],
                    seedBytes[5],
                ]
            }
            if (clockseq == null) {
                clockseq = _clockseq = ((seedBytes[6] << 8) | seedBytes[7]) & 16383
            }
        }
        let msecs = options.msecs !== undefined ? options.msecs : Date.now()
        let nsecs = options.nsecs !== undefined ? options.nsecs : _lastNSecs + 1
        const dt = msecs - _lastMSecs + (nsecs - _lastNSecs) / 1e4
        if (dt < 0 && options.clockseq === undefined) {
            clockseq = (clockseq + 1) & 16383
        }
        if ((dt < 0 || msecs > _lastMSecs) && options.nsecs === undefined) {
            nsecs = 0
        }
        if (nsecs >= 1e4) {
            throw new Error("uuid.v1(): Can't create more than 10M uuids/sec")
        }
        _lastMSecs = msecs
        _lastNSecs = nsecs
        _clockseq = clockseq
        msecs += 12219292800000
        const tl = ((msecs & 268435455) * 1e4 + nsecs) % 4294967296
        b[i++] = (tl >>> 24) & 255
        b[i++] = (tl >>> 16) & 255
        b[i++] = (tl >>> 8) & 255
        b[i++] = tl & 255
        const tmh = ((msecs / 4294967296) * 1e4) & 268435455
        b[i++] = (tmh >>> 8) & 255
        b[i++] = tmh & 255
        b[i++] = ((tmh >>> 24) & 15) | 16
        b[i++] = (tmh >>> 16) & 255
        b[i++] = (clockseq >>> 8) | 128
        b[i++] = clockseq & 255
        for (let n = 0; n < 6; ++n) {
            b[i + n] = node[n]
        }
        return buf || (0, _stringify.default)(b)
    }
    Object.defineProperty(exports, '__esModule', {
        value: true,
    })
    exports.default = undefined
    var _rng = _interopRequireDefault(require_rng())
    var _stringify = _interopRequireDefault(require_stringify())
    var _nodeId
    var _clockseq
    var _lastMSecs = 0
    var _lastNSecs = 0
    var _default = v1
    exports.default = _default
})

// node_modules/uuid/dist/parse.js
var require_parse = __commonJS((exports) => {
    var _interopRequireDefault = (obj) => (obj && obj.__esModule ? obj : { default: obj })
    var parse = (uuid) => {
        if (!(0, _validate.default)(uuid)) {
            throw TypeError('Invalid UUID')
        }
        let v
        const arr = new Uint8Array(16)
        arr[0] = (v = Number.parseInt(uuid.slice(0, 8), 16)) >>> 24
        arr[1] = (v >>> 16) & 255
        arr[2] = (v >>> 8) & 255
        arr[3] = v & 255
        arr[4] = (v = Number.parseInt(uuid.slice(9, 13), 16)) >>> 8
        arr[5] = v & 255
        arr[6] = (v = Number.parseInt(uuid.slice(14, 18), 16)) >>> 8
        arr[7] = v & 255
        arr[8] = (v = Number.parseInt(uuid.slice(19, 23), 16)) >>> 8
        arr[9] = v & 255
        arr[10] = ((v = Number.parseInt(uuid.slice(24, 36), 16)) / 1099511627776) & 255
        arr[11] = (v / 4294967296) & 255
        arr[12] = (v >>> 24) & 255
        arr[13] = (v >>> 16) & 255
        arr[14] = (v >>> 8) & 255
        arr[15] = v & 255
        return arr
    }
    Object.defineProperty(exports, '__esModule', {
        value: true,
    })
    exports.default = undefined
    var _validate = _interopRequireDefault(require_validate())
    var _default = parse
    exports.default = _default
})

// node_modules/uuid/dist/v35.js
var require_v35 = __commonJS((exports) => {
    var _interopRequireDefault = (obj) => (obj && obj.__esModule ? obj : { default: obj })
    var stringToBytes = (str) => {
        str = unescape(encodeURIComponent(str))
        const bytes = []
        for (let i = 0; i < str.length; ++i) {
            bytes.push(str.charCodeAt(i))
        }
        return bytes
    }
    var _default = (name, version, hashfunc) => {
        function generateUUID(value, namespace, buf, offset) {
            if (typeof value === 'string') {
                value = stringToBytes(value)
            }
            if (typeof namespace === 'string') {
                namespace = (0, _parse.default)(namespace)
            }
            if (namespace.length !== 16) {
                throw TypeError('Namespace must be array-like (16 iterable integer values, 0-255)')
            }
            let bytes = new Uint8Array(16 + value.length)
            bytes.set(namespace)
            bytes.set(value, namespace.length)
            bytes = hashfunc(bytes)
            bytes[6] = (bytes[6] & 15) | version
            bytes[8] = (bytes[8] & 63) | 128
            if (buf) {
                offset = offset || 0
                for (let i = 0; i < 16; ++i) {
                    buf[offset + i] = bytes[i]
                }
                return buf
            }
            return (0, _stringify.default)(bytes)
        }
        try {
            generateUUID.name = name
        } catch (err) {}
        generateUUID.DNS = DNS
        generateUUID.URL = URL2
        return generateUUID
    }
    Object.defineProperty(exports, '__esModule', {
        value: true,
    })
    exports.default = _default
    exports.URL = exports.DNS = undefined
    var _stringify = _interopRequireDefault(require_stringify())
    var _parse = _interopRequireDefault(require_parse())
    var DNS = '6ba7b810-9dad-11d1-80b4-00c04fd430c8'
    exports.DNS = DNS
    var URL2 = '6ba7b811-9dad-11d1-80b4-00c04fd430c8'
    exports.URL = URL2
})

// node_modules/uuid/dist/md5.js
var require_md5 = __commonJS((exports) => {
    var _interopRequireDefault = (obj) => (obj && obj.__esModule ? obj : { default: obj })
    var md5 = (bytes) => {
        if (Array.isArray(bytes)) {
            bytes = Buffer.from(bytes)
        } else if (typeof bytes === 'string') {
            bytes = Buffer.from(bytes, 'utf8')
        }
        return _crypto.default.createHash('md5').update(bytes).digest()
    }
    Object.defineProperty(exports, '__esModule', {
        value: true,
    })
    exports.default = undefined
    var _crypto = _interopRequireDefault(import.meta.require('crypto'))
    var _default = md5
    exports.default = _default
})

// node_modules/uuid/dist/v3.js
var require_v3 = __commonJS((exports) => {
    var _interopRequireDefault = (obj) => (obj && obj.__esModule ? obj : { default: obj })
    Object.defineProperty(exports, '__esModule', {
        value: true,
    })
    exports.default = undefined
    var _v = _interopRequireDefault(require_v35())
    var _md = _interopRequireDefault(require_md5())
    var v3 = (0, _v.default)('v3', 48, _md.default)
    var _default = v3
    exports.default = _default
})

// node_modules/uuid/dist/v4.js
var require_v4 = __commonJS((exports) => {
    var _interopRequireDefault = (obj) => (obj && obj.__esModule ? obj : { default: obj })
    var v4 = (options, buf, offset) => {
        options = options || {}
        const rnds = options.random || (options.rng || _rng.default)()
        rnds[6] = (rnds[6] & 15) | 64
        rnds[8] = (rnds[8] & 63) | 128
        if (buf) {
            offset = offset || 0
            for (let i = 0; i < 16; ++i) {
                buf[offset + i] = rnds[i]
            }
            return buf
        }
        return (0, _stringify.default)(rnds)
    }
    Object.defineProperty(exports, '__esModule', {
        value: true,
    })
    exports.default = undefined
    var _rng = _interopRequireDefault(require_rng())
    var _stringify = _interopRequireDefault(require_stringify())
    var _default = v4
    exports.default = _default
})

// node_modules/uuid/dist/sha1.js
var require_sha1 = __commonJS((exports) => {
    var _interopRequireDefault = (obj) => (obj && obj.__esModule ? obj : { default: obj })
    var sha1 = (bytes) => {
        if (Array.isArray(bytes)) {
            bytes = Buffer.from(bytes)
        } else if (typeof bytes === 'string') {
            bytes = Buffer.from(bytes, 'utf8')
        }
        return _crypto.default.createHash('sha1').update(bytes).digest()
    }
    Object.defineProperty(exports, '__esModule', {
        value: true,
    })
    exports.default = undefined
    var _crypto = _interopRequireDefault(import.meta.require('crypto'))
    var _default = sha1
    exports.default = _default
})

// node_modules/uuid/dist/v5.js
var require_v5 = __commonJS((exports) => {
    var _interopRequireDefault = (obj) => (obj && obj.__esModule ? obj : { default: obj })
    Object.defineProperty(exports, '__esModule', {
        value: true,
    })
    exports.default = undefined
    var _v = _interopRequireDefault(require_v35())
    var _sha = _interopRequireDefault(require_sha1())
    var v5 = (0, _v.default)('v5', 80, _sha.default)
    var _default = v5
    exports.default = _default
})

// node_modules/uuid/dist/nil.js
var require_nil = __commonJS((exports) => {
    Object.defineProperty(exports, '__esModule', {
        value: true,
    })
    exports.default = undefined
    var _default = '00000000-0000-0000-0000-000000000000'
    exports.default = _default
})

// node_modules/uuid/dist/version.js
var require_version = __commonJS((exports) => {
    var _interopRequireDefault = (obj) => (obj && obj.__esModule ? obj : { default: obj })
    var version = (uuid) => {
        if (!(0, _validate.default)(uuid)) {
            throw TypeError('Invalid UUID')
        }
        return Number.parseInt(uuid.substr(14, 1), 16)
    }
    Object.defineProperty(exports, '__esModule', {
        value: true,
    })
    exports.default = undefined
    var _validate = _interopRequireDefault(require_validate())
    var _default = version
    exports.default = _default
})

// node_modules/uuid/dist/index.js
var require_dist = __commonJS((exports) => {
    var _interopRequireDefault = (obj) => (obj && obj.__esModule ? obj : { default: obj })
    Object.defineProperty(exports, '__esModule', {
        value: true,
    })
    Object.defineProperty(exports, 'v1', {
        enumerable: true,
        get: () => _v.default,
    })
    Object.defineProperty(exports, 'v3', {
        enumerable: true,
        get: () => _v2.default,
    })
    Object.defineProperty(exports, 'v4', {
        enumerable: true,
        get: () => _v3.default,
    })
    Object.defineProperty(exports, 'v5', {
        enumerable: true,
        get: () => _v4.default,
    })
    Object.defineProperty(exports, 'NIL', {
        enumerable: true,
        get: () => _nil.default,
    })
    Object.defineProperty(exports, 'version', {
        enumerable: true,
        get: () => _version.default,
    })
    Object.defineProperty(exports, 'validate', {
        enumerable: true,
        get: () => _validate.default,
    })
    Object.defineProperty(exports, 'stringify', {
        enumerable: true,
        get: () => _stringify.default,
    })
    Object.defineProperty(exports, 'parse', {
        enumerable: true,
        get: () => _parse.default,
    })
    var _v = _interopRequireDefault(require_v1())
    var _v2 = _interopRequireDefault(require_v3())
    var _v3 = _interopRequireDefault(require_v4())
    var _v4 = _interopRequireDefault(require_v5())
    var _nil = _interopRequireDefault(require_nil())
    var _version = _interopRequireDefault(require_version())
    var _validate = _interopRequireDefault(require_validate())
    var _stringify = _interopRequireDefault(require_stringify())
    var _parse = _interopRequireDefault(require_parse())
})

// node_modules/@actions/core/lib/file-command.js
var require_file_command = __commonJS((exports) => {
    var issueFileCommand = (command, message) => {
        const filePath = process.env[`GITHUB_${command}`]
        if (!filePath) {
            throw new Error(`Unable to find environment variable for file command ${command}`)
        }
        if (!fs.existsSync(filePath)) {
            throw new Error(`Missing file at path: ${filePath}`)
        }
        fs.appendFileSync(filePath, `${utils_1.toCommandValue(message)}${os.EOL}`, {
            encoding: 'utf8',
        })
    }
    var prepareKeyValueMessage = (key, value) => {
        const delimiter = `ghadelimiter_${uuid_1.v4()}`
        const convertedValue = utils_1.toCommandValue(value)
        if (key.includes(delimiter)) {
            throw new Error(
                `Unexpected input: name should not contain the delimiter "${delimiter}"`
            )
        }
        if (convertedValue.includes(delimiter)) {
            throw new Error(
                `Unexpected input: value should not contain the delimiter "${delimiter}"`
            )
        }
        return `${key}<<${delimiter}${os.EOL}${convertedValue}${os.EOL}${delimiter}`
    }
    var __createBinding =
        (exports && exports.__createBinding) ||
        (Object.create
            ? (o, m, k, k2) => {
                  if (k2 === undefined) k2 = k
                  Object.defineProperty(o, k2, { enumerable: true, get: () => m[k] })
              }
            : (o, m, k, k2) => {
                  if (k2 === undefined) k2 = k
                  o[k2] = m[k]
              })
    var __setModuleDefault =
        (exports && exports.__setModuleDefault) ||
        (Object.create
            ? (o, v) => {
                  Object.defineProperty(o, 'default', { enumerable: true, value: v })
              }
            : (o, v) => {
                  o['default'] = v
              })
    var __importStar =
        (exports && exports.__importStar) ||
        ((mod) => {
            if (mod && mod.__esModule) return mod
            var result = {}
            if (mod != null) {
                for (var k in mod)
                    if (k !== 'default' && Object.hasOwnProperty.call(mod, k))
                        __createBinding(result, mod, k)
            }
            __setModuleDefault(result, mod)
            return result
        })
    Object.defineProperty(exports, '__esModule', { value: true })
    exports.prepareKeyValueMessage = exports.issueFileCommand = undefined
    var fs = __importStar(import.meta.require('fs'))
    var os = __importStar(import.meta.require('os'))
    var uuid_1 = require_dist()
    var utils_1 = require_utils()
    exports.issueFileCommand = issueFileCommand
    exports.prepareKeyValueMessage = prepareKeyValueMessage
})

// node_modules/@actions/http-client/lib/proxy.js
var require_proxy = __commonJS((exports) => {
    var getProxyUrl = (reqUrl) => {
        const usingSsl = reqUrl.protocol === 'https:'
        if (checkBypass(reqUrl)) {
            return
        }
        const proxyVar = (() => {
            if (usingSsl) {
                return process.env['https_proxy'] || process.env['HTTPS_PROXY']
            } else {
                return process.env['http_proxy'] || process.env['HTTP_PROXY']
            }
        })()
        if (proxyVar) {
            try {
                return new URL(proxyVar)
            } catch (_a) {
                if (!proxyVar.startsWith('http://') && !proxyVar.startsWith('https://'))
                    return new URL(`http://${proxyVar}`)
            }
        } else {
            return
        }
    }
    var checkBypass = (reqUrl) => {
        if (!reqUrl.hostname) {
            return false
        }
        const reqHost = reqUrl.hostname
        if (isLoopbackAddress(reqHost)) {
            return true
        }
        const noProxy = process.env['no_proxy'] || process.env['NO_PROXY'] || ''
        if (!noProxy) {
            return false
        }
        let reqPort
        if (reqUrl.port) {
            reqPort = Number(reqUrl.port)
        } else if (reqUrl.protocol === 'http:') {
            reqPort = 80
        } else if (reqUrl.protocol === 'https:') {
            reqPort = 443
        }
        const upperReqHosts = [reqUrl.hostname.toUpperCase()]
        if (typeof reqPort === 'number') {
            upperReqHosts.push(`${upperReqHosts[0]}:${reqPort}`)
        }
        for (const upperNoProxyItem of noProxy
            .split(',')
            .map((x) => x.trim().toUpperCase())
            .filter((x) => x)) {
            if (
                upperNoProxyItem === '*' ||
                upperReqHosts.some(
                    (x) =>
                        x === upperNoProxyItem ||
                        x.endsWith(`.${upperNoProxyItem}`) ||
                        (upperNoProxyItem.startsWith('.') && x.endsWith(`${upperNoProxyItem}`))
                )
            ) {
                return true
            }
        }
        return false
    }
    var isLoopbackAddress = (host) => {
        const hostLower = host.toLowerCase()
        return (
            hostLower === 'localhost' ||
            hostLower.startsWith('127.') ||
            hostLower.startsWith('[::1]') ||
            hostLower.startsWith('[0:0:0:0:0:0:0:1]')
        )
    }
    Object.defineProperty(exports, '__esModule', { value: true })
    exports.checkBypass = exports.getProxyUrl = undefined
    exports.getProxyUrl = getProxyUrl
    exports.checkBypass = checkBypass
})

// node_modules/tunnel/lib/tunnel.js
var require_tunnel = __commonJS((exports) => {
    var httpOverHttp = (options) => {
        var agent = new TunnelingAgent(options)
        agent.request = http.request
        return agent
    }
    var httpsOverHttp = (options) => {
        var agent = new TunnelingAgent(options)
        agent.request = http.request
        agent.createSocket = createSecureSocket
        agent.defaultPort = 443
        return agent
    }
    var httpOverHttps = (options) => {
        var agent = new TunnelingAgent(options)
        agent.request = https.request
        return agent
    }
    var httpsOverHttps = (options) => {
        var agent = new TunnelingAgent(options)
        agent.request = https.request
        agent.createSocket = createSecureSocket
        agent.defaultPort = 443
        return agent
    }
    var TunnelingAgent = function (options) {
        var self = this
        self.options = options || {}
        self.proxyOptions = self.options.proxy || {}
        self.maxSockets = self.options.maxSockets || http.Agent.defaultMaxSockets
        self.requests = []
        self.sockets = []
        self.on('free', function onFree(socket, host, port, localAddress) {
            var options2 = toOptions(host, port, localAddress)
            for (var i = 0, len = self.requests.length; i < len; ++i) {
                var pending = self.requests[i]
                if (pending.host === options2.host && pending.port === options2.port) {
                    self.requests.splice(i, 1)
                    pending.request.onSocket(socket)
                    return
                }
            }
            socket.destroy()
            self.removeSocket(socket)
        })
    }
    var createSecureSocket = function (options, cb) {
        TunnelingAgent.prototype.createSocket.call(this, options, (socket) => {
            var hostHeader = options.request.getHeader('host')
            var tlsOptions = mergeOptions({}, this.options, {
                socket,
                servername: hostHeader ? hostHeader.replace(/:.*$/, '') : options.host,
            })
            var secureSocket = tls.connect(0, tlsOptions)
            this.sockets[this.sockets.indexOf(socket)] = secureSocket
            cb(secureSocket)
        })
    }
    var toOptions = (host, port, localAddress) => {
        if (typeof host === 'string') {
            return {
                host,
                port,
                localAddress,
            }
        }
        return host
    }
    var mergeOptions = (target) => {
        for (var i = 1, len = arguments.length; i < len; ++i) {
            var overrides = arguments[i]
            if (typeof overrides === 'object') {
                var keys = Object.keys(overrides)
                for (var j = 0, keyLen = keys.length; j < keyLen; ++j) {
                    var k = keys[j]
                    if (overrides[k] !== undefined) {
                        target[k] = overrides[k]
                    }
                }
            }
        }
        return target
    }
    var net = import.meta.require('net')
    var tls = import.meta.require('tls')
    var http = import.meta.require('http')
    var https = import.meta.require('https')
    var events = import.meta.require('events')
    var assert = import.meta.require('assert')
    var util = import.meta.require('util')
    exports.httpOverHttp = httpOverHttp
    exports.httpsOverHttp = httpsOverHttp
    exports.httpOverHttps = httpOverHttps
    exports.httpsOverHttps = httpsOverHttps
    util.inherits(TunnelingAgent, events.EventEmitter)
    TunnelingAgent.prototype.addRequest = function addRequest(req, host, port, localAddress) {
        var self = this
        var options = mergeOptions(
            { request: req },
            self.options,
            toOptions(host, port, localAddress)
        )
        if (self.sockets.length >= this.maxSockets) {
            self.requests.push(options)
            return
        }
        self.createSocket(options, (socket) => {
            socket.on('free', onFree)
            socket.on('close', onCloseOrRemove)
            socket.on('agentRemove', onCloseOrRemove)
            req.onSocket(socket)
            function onFree() {
                self.emit('free', socket, options)
            }
            function onCloseOrRemove(err) {
                self.removeSocket(socket)
                socket.removeListener('free', onFree)
                socket.removeListener('close', onCloseOrRemove)
                socket.removeListener('agentRemove', onCloseOrRemove)
            }
        })
    }
    TunnelingAgent.prototype.createSocket = function createSocket(options, cb) {
        var self = this
        var placeholder = {}
        self.sockets.push(placeholder)
        var connectOptions = mergeOptions({}, self.proxyOptions, {
            method: 'CONNECT',
            path: options.host + ':' + options.port,
            agent: false,
            headers: {
                host: options.host + ':' + options.port,
            },
        })
        if (options.localAddress) {
            connectOptions.localAddress = options.localAddress
        }
        if (connectOptions.proxyAuth) {
            connectOptions.headers = connectOptions.headers || {}
            connectOptions.headers['Proxy-Authorization'] =
                'Basic ' + new Buffer(connectOptions.proxyAuth).toString('base64')
        }
        debug('making CONNECT request')
        var connectReq = self.request(connectOptions)
        connectReq.useChunkedEncodingByDefault = false
        connectReq.once('response', onResponse)
        connectReq.once('upgrade', onUpgrade)
        connectReq.once('connect', onConnect)
        connectReq.once('error', onError)
        connectReq.end()
        function onResponse(res) {
            res.upgrade = true
        }
        function onUpgrade(res, socket, head) {
            process.nextTick(() => {
                onConnect(res, socket, head)
            })
        }
        function onConnect(res, socket, head) {
            connectReq.removeAllListeners()
            socket.removeAllListeners()
            if (res.statusCode !== 200) {
                debug('tunneling socket could not be established, statusCode=%d', res.statusCode)
                socket.destroy()
                var error = new Error(
                    'tunneling socket could not be established, statusCode=' + res.statusCode
                )
                error.code = 'ECONNRESET'
                options.request.emit('error', error)
                self.removeSocket(placeholder)
                return
            }
            if (head.length > 0) {
                debug('got illegal response body from proxy')
                socket.destroy()
                var error = new Error('got illegal response body from proxy')
                error.code = 'ECONNRESET'
                options.request.emit('error', error)
                self.removeSocket(placeholder)
                return
            }
            debug('tunneling connection has established')
            self.sockets[self.sockets.indexOf(placeholder)] = socket
            return cb(socket)
        }
        function onError(cause) {
            connectReq.removeAllListeners()
            debug(
                'tunneling socket could not be established, cause=%s\n',
                cause.message,
                cause.stack
            )
            var error = new Error(
                'tunneling socket could not be established, cause=' + cause.message
            )
            error.code = 'ECONNRESET'
            options.request.emit('error', error)
            self.removeSocket(placeholder)
        }
    }
    TunnelingAgent.prototype.removeSocket = function removeSocket(socket) {
        var pos = this.sockets.indexOf(socket)
        if (pos === -1) {
            return
        }
        this.sockets.splice(pos, 1)
        var pending = this.requests.shift()
        if (pending) {
            this.createSocket(pending, (socket2) => {
                pending.request.onSocket(socket2)
            })
        }
    }
    var debug
    if (process.env.NODE_DEBUG && /\btunnel\b/.test(process.env.NODE_DEBUG)) {
        debug = () => {
            var args = Array.prototype.slice.call(arguments)
            if (typeof args[0] === 'string') {
                args[0] = 'TUNNEL: ' + args[0]
            } else {
                args.unshift('TUNNEL:')
            }
            console.error.apply(console, args)
        }
    } else {
        debug = () => {}
    }
    exports.debug = debug
})

// node_modules/@actions/http-client/lib/index.js
var require_lib = __commonJS((exports) => {
    var getProxyUrl = (serverUrl) => {
        const proxyUrl = pm.getProxyUrl(new URL(serverUrl))
        return proxyUrl ? proxyUrl.href : ''
    }
    var isHttps = (requestUrl) => {
        const parsedUrl = new URL(requestUrl)
        return parsedUrl.protocol === 'https:'
    }
    var __createBinding =
        (exports && exports.__createBinding) ||
        (Object.create
            ? (o, m, k, k2) => {
                  if (k2 === undefined) k2 = k
                  var desc = Object.getOwnPropertyDescriptor(m, k)
                  if (
                      !desc ||
                      ('get' in desc ? !m.__esModule : desc.writable || desc.configurable)
                  ) {
                      desc = { enumerable: true, get: () => m[k] }
                  }
                  Object.defineProperty(o, k2, desc)
              }
            : (o, m, k, k2) => {
                  if (k2 === undefined) k2 = k
                  o[k2] = m[k]
              })
    var __setModuleDefault =
        (exports && exports.__setModuleDefault) ||
        (Object.create
            ? (o, v) => {
                  Object.defineProperty(o, 'default', { enumerable: true, value: v })
              }
            : (o, v) => {
                  o['default'] = v
              })
    var __importStar =
        (exports && exports.__importStar) ||
        ((mod) => {
            if (mod && mod.__esModule) return mod
            var result = {}
            if (mod != null) {
                for (var k in mod)
                    if (k !== 'default' && Object.prototype.hasOwnProperty.call(mod, k))
                        __createBinding(result, mod, k)
            }
            __setModuleDefault(result, mod)
            return result
        })
    var __awaiter =
        (exports && exports.__awaiter) ||
        ((thisArg, _arguments, P, generator) => {
            function adopt(value) {
                return value instanceof P
                    ? value
                    : new P((resolve) => {
                          resolve(value)
                      })
            }
            return new (P || (P = Promise))((resolve, reject) => {
                function fulfilled(value) {
                    try {
                        step(generator.next(value))
                    } catch (e) {
                        reject(e)
                    }
                }
                function rejected(value) {
                    try {
                        step(generator['throw'](value))
                    } catch (e) {
                        reject(e)
                    }
                }
                function step(result) {
                    result.done
                        ? resolve(result.value)
                        : adopt(result.value).then(fulfilled, rejected)
                }
                step((generator = generator.apply(thisArg, _arguments || [])).next())
            })
        })
    Object.defineProperty(exports, '__esModule', { value: true })
    exports.HttpClient =
        exports.isHttps =
        exports.HttpClientResponse =
        exports.HttpClientError =
        exports.getProxyUrl =
        exports.MediaTypes =
        exports.Headers =
        exports.HttpCodes =
            undefined
    var http = __importStar(import.meta.require('http'))
    var https = __importStar(import.meta.require('https'))
    var pm = __importStar(require_proxy())
    var tunnel = __importStar(require_tunnel())
    var undici_1 = import.meta.require('undici')
    var HttpCodes
    ;((HttpCodes2) => {
        HttpCodes2[(HttpCodes2['OK'] = 200)] = 'OK'
        HttpCodes2[(HttpCodes2['MultipleChoices'] = 300)] = 'MultipleChoices'
        HttpCodes2[(HttpCodes2['MovedPermanently'] = 301)] = 'MovedPermanently'
        HttpCodes2[(HttpCodes2['ResourceMoved'] = 302)] = 'ResourceMoved'
        HttpCodes2[(HttpCodes2['SeeOther'] = 303)] = 'SeeOther'
        HttpCodes2[(HttpCodes2['NotModified'] = 304)] = 'NotModified'
        HttpCodes2[(HttpCodes2['UseProxy'] = 305)] = 'UseProxy'
        HttpCodes2[(HttpCodes2['SwitchProxy'] = 306)] = 'SwitchProxy'
        HttpCodes2[(HttpCodes2['TemporaryRedirect'] = 307)] = 'TemporaryRedirect'
        HttpCodes2[(HttpCodes2['PermanentRedirect'] = 308)] = 'PermanentRedirect'
        HttpCodes2[(HttpCodes2['BadRequest'] = 400)] = 'BadRequest'
        HttpCodes2[(HttpCodes2['Unauthorized'] = 401)] = 'Unauthorized'
        HttpCodes2[(HttpCodes2['PaymentRequired'] = 402)] = 'PaymentRequired'
        HttpCodes2[(HttpCodes2['Forbidden'] = 403)] = 'Forbidden'
        HttpCodes2[(HttpCodes2['NotFound'] = 404)] = 'NotFound'
        HttpCodes2[(HttpCodes2['MethodNotAllowed'] = 405)] = 'MethodNotAllowed'
        HttpCodes2[(HttpCodes2['NotAcceptable'] = 406)] = 'NotAcceptable'
        HttpCodes2[(HttpCodes2['ProxyAuthenticationRequired'] = 407)] =
            'ProxyAuthenticationRequired'
        HttpCodes2[(HttpCodes2['RequestTimeout'] = 408)] = 'RequestTimeout'
        HttpCodes2[(HttpCodes2['Conflict'] = 409)] = 'Conflict'
        HttpCodes2[(HttpCodes2['Gone'] = 410)] = 'Gone'
        HttpCodes2[(HttpCodes2['TooManyRequests'] = 429)] = 'TooManyRequests'
        HttpCodes2[(HttpCodes2['InternalServerError'] = 500)] = 'InternalServerError'
        HttpCodes2[(HttpCodes2['NotImplemented'] = 501)] = 'NotImplemented'
        HttpCodes2[(HttpCodes2['BadGateway'] = 502)] = 'BadGateway'
        HttpCodes2[(HttpCodes2['ServiceUnavailable'] = 503)] = 'ServiceUnavailable'
        HttpCodes2[(HttpCodes2['GatewayTimeout'] = 504)] = 'GatewayTimeout'
    })(HttpCodes || (exports.HttpCodes = HttpCodes = {}))
    var Headers
    ;((Headers2) => {
        Headers2['Accept'] = 'accept'
        Headers2['ContentType'] = 'content-type'
    })(Headers || (exports.Headers = Headers = {}))
    var MediaTypes
    ;((MediaTypes2) => {
        MediaTypes2['ApplicationJson'] = 'application/json'
    })(MediaTypes || (exports.MediaTypes = MediaTypes = {}))
    exports.getProxyUrl = getProxyUrl
    var HttpRedirectCodes = [
        HttpCodes.MovedPermanently,
        HttpCodes.ResourceMoved,
        HttpCodes.SeeOther,
        HttpCodes.TemporaryRedirect,
        HttpCodes.PermanentRedirect,
    ]
    var HttpResponseRetryCodes = [
        HttpCodes.BadGateway,
        HttpCodes.ServiceUnavailable,
        HttpCodes.GatewayTimeout,
    ]
    var RetryableHttpVerbs = ['OPTIONS', 'GET', 'DELETE', 'HEAD']
    var ExponentialBackoffCeiling = 10
    var ExponentialBackoffTimeSlice = 5

    class HttpClientError extends Error {
        constructor(message, statusCode) {
            super(message)
            this.name = 'HttpClientError'
            this.statusCode = statusCode
            Object.setPrototypeOf(this, HttpClientError.prototype)
        }
    }
    exports.HttpClientError = HttpClientError

    class HttpClientResponse {
        constructor(message) {
            this.message = message
        }
        readBody() {
            return __awaiter(this, undefined, undefined, function* () {
                return new Promise((resolve) =>
                    __awaiter(this, undefined, undefined, function* () {
                        let output = Buffer.alloc(0)
                        this.message.on('data', (chunk) => {
                            output = Buffer.concat([output, chunk])
                        })
                        this.message.on('end', () => {
                            resolve(output.toString())
                        })
                    })
                )
            })
        }
        readBodyBuffer() {
            return __awaiter(this, undefined, undefined, function* () {
                return new Promise((resolve) =>
                    __awaiter(this, undefined, undefined, function* () {
                        const chunks = []
                        this.message.on('data', (chunk) => {
                            chunks.push(chunk)
                        })
                        this.message.on('end', () => {
                            resolve(Buffer.concat(chunks))
                        })
                    })
                )
            })
        }
    }
    exports.HttpClientResponse = HttpClientResponse
    exports.isHttps = isHttps

    class HttpClient {
        constructor(userAgent, handlers, requestOptions) {
            this._ignoreSslError = false
            this._allowRedirects = true
            this._allowRedirectDowngrade = false
            this._maxRedirects = 50
            this._allowRetries = false
            this._maxRetries = 1
            this._keepAlive = false
            this._disposed = false
            this.userAgent = userAgent
            this.handlers = handlers || []
            this.requestOptions = requestOptions
            if (requestOptions) {
                if (requestOptions.ignoreSslError != null) {
                    this._ignoreSslError = requestOptions.ignoreSslError
                }
                this._socketTimeout = requestOptions.socketTimeout
                if (requestOptions.allowRedirects != null) {
                    this._allowRedirects = requestOptions.allowRedirects
                }
                if (requestOptions.allowRedirectDowngrade != null) {
                    this._allowRedirectDowngrade = requestOptions.allowRedirectDowngrade
                }
                if (requestOptions.maxRedirects != null) {
                    this._maxRedirects = Math.max(requestOptions.maxRedirects, 0)
                }
                if (requestOptions.keepAlive != null) {
                    this._keepAlive = requestOptions.keepAlive
                }
                if (requestOptions.allowRetries != null) {
                    this._allowRetries = requestOptions.allowRetries
                }
                if (requestOptions.maxRetries != null) {
                    this._maxRetries = requestOptions.maxRetries
                }
            }
        }
        options(requestUrl, additionalHeaders) {
            return __awaiter(this, undefined, undefined, function* () {
                return this.request('OPTIONS', requestUrl, null, additionalHeaders || {})
            })
        }
        get(requestUrl, additionalHeaders) {
            return __awaiter(this, undefined, undefined, function* () {
                return this.request('GET', requestUrl, null, additionalHeaders || {})
            })
        }
        del(requestUrl, additionalHeaders) {
            return __awaiter(this, undefined, undefined, function* () {
                return this.request('DELETE', requestUrl, null, additionalHeaders || {})
            })
        }
        post(requestUrl, data, additionalHeaders) {
            return __awaiter(this, undefined, undefined, function* () {
                return this.request('POST', requestUrl, data, additionalHeaders || {})
            })
        }
        patch(requestUrl, data, additionalHeaders) {
            return __awaiter(this, undefined, undefined, function* () {
                return this.request('PATCH', requestUrl, data, additionalHeaders || {})
            })
        }
        put(requestUrl, data, additionalHeaders) {
            return __awaiter(this, undefined, undefined, function* () {
                return this.request('PUT', requestUrl, data, additionalHeaders || {})
            })
        }
        head(requestUrl, additionalHeaders) {
            return __awaiter(this, undefined, undefined, function* () {
                return this.request('HEAD', requestUrl, null, additionalHeaders || {})
            })
        }
        sendStream(verb, requestUrl, stream, additionalHeaders) {
            return __awaiter(this, undefined, undefined, function* () {
                return this.request(verb, requestUrl, stream, additionalHeaders)
            })
        }
        getJson(requestUrl, additionalHeaders = {}) {
            return __awaiter(this, undefined, undefined, function* () {
                additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(
                    additionalHeaders,
                    Headers.Accept,
                    MediaTypes.ApplicationJson
                )
                const res = yield this.get(requestUrl, additionalHeaders)
                return this._processResponse(res, this.requestOptions)
            })
        }
        postJson(requestUrl, obj, additionalHeaders = {}) {
            return __awaiter(this, undefined, undefined, function* () {
                const data = JSON.stringify(obj, null, 2)
                additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(
                    additionalHeaders,
                    Headers.Accept,
                    MediaTypes.ApplicationJson
                )
                additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(
                    additionalHeaders,
                    Headers.ContentType,
                    MediaTypes.ApplicationJson
                )
                const res = yield this.post(requestUrl, data, additionalHeaders)
                return this._processResponse(res, this.requestOptions)
            })
        }
        putJson(requestUrl, obj, additionalHeaders = {}) {
            return __awaiter(this, undefined, undefined, function* () {
                const data = JSON.stringify(obj, null, 2)
                additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(
                    additionalHeaders,
                    Headers.Accept,
                    MediaTypes.ApplicationJson
                )
                additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(
                    additionalHeaders,
                    Headers.ContentType,
                    MediaTypes.ApplicationJson
                )
                const res = yield this.put(requestUrl, data, additionalHeaders)
                return this._processResponse(res, this.requestOptions)
            })
        }
        patchJson(requestUrl, obj, additionalHeaders = {}) {
            return __awaiter(this, undefined, undefined, function* () {
                const data = JSON.stringify(obj, null, 2)
                additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(
                    additionalHeaders,
                    Headers.Accept,
                    MediaTypes.ApplicationJson
                )
                additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(
                    additionalHeaders,
                    Headers.ContentType,
                    MediaTypes.ApplicationJson
                )
                const res = yield this.patch(requestUrl, data, additionalHeaders)
                return this._processResponse(res, this.requestOptions)
            })
        }
        request(verb, requestUrl, data, headers) {
            return __awaiter(this, undefined, undefined, function* () {
                if (this._disposed) {
                    throw new Error('Client has already been disposed.')
                }
                const parsedUrl = new URL(requestUrl)
                let info = this._prepareRequest(verb, parsedUrl, headers)
                const maxTries =
                    this._allowRetries && RetryableHttpVerbs.includes(verb)
                        ? this._maxRetries + 1
                        : 1
                let numTries = 0
                let response
                do {
                    response = yield this.requestRaw(info, data)
                    if (
                        response &&
                        response.message &&
                        response.message.statusCode === HttpCodes.Unauthorized
                    ) {
                        let authenticationHandler
                        for (const handler of this.handlers) {
                            if (handler.canHandleAuthentication(response)) {
                                authenticationHandler = handler
                                break
                            }
                        }
                        if (authenticationHandler) {
                            return authenticationHandler.handleAuthentication(this, info, data)
                        } else {
                            return response
                        }
                    }
                    let redirectsRemaining = this._maxRedirects
                    while (
                        response.message.statusCode &&
                        HttpRedirectCodes.includes(response.message.statusCode) &&
                        this._allowRedirects &&
                        redirectsRemaining > 0
                    ) {
                        const redirectUrl = response.message.headers['location']
                        if (!redirectUrl) {
                            break
                        }
                        const parsedRedirectUrl = new URL(redirectUrl)
                        if (
                            parsedUrl.protocol === 'https:' &&
                            parsedUrl.protocol !== parsedRedirectUrl.protocol &&
                            !this._allowRedirectDowngrade
                        ) {
                            throw new Error(
                                'Redirect from HTTPS to HTTP protocol. This downgrade is not allowed for security reasons. If you want to allow this behavior, set the allowRedirectDowngrade option to true.'
                            )
                        }
                        yield response.readBody()
                        if (parsedRedirectUrl.hostname !== parsedUrl.hostname) {
                            for (const header in headers) {
                                if (header.toLowerCase() === 'authorization') {
                                    delete headers[header]
                                }
                            }
                        }
                        info = this._prepareRequest(verb, parsedRedirectUrl, headers)
                        response = yield this.requestRaw(info, data)
                        redirectsRemaining--
                    }
                    if (
                        !response.message.statusCode ||
                        !HttpResponseRetryCodes.includes(response.message.statusCode)
                    ) {
                        return response
                    }
                    numTries += 1
                    if (numTries < maxTries) {
                        yield response.readBody()
                        yield this._performExponentialBackoff(numTries)
                    }
                } while (numTries < maxTries)
                return response
            })
        }
        dispose() {
            if (this._agent) {
                this._agent.destroy()
            }
            this._disposed = true
        }
        requestRaw(info, data) {
            return __awaiter(this, undefined, undefined, function* () {
                return new Promise((resolve, reject) => {
                    function callbackForResult(err, res) {
                        if (err) {
                            reject(err)
                        } else if (!res) {
                            reject(new Error('Unknown error'))
                        } else {
                            resolve(res)
                        }
                    }
                    this.requestRawWithCallback(info, data, callbackForResult)
                })
            })
        }
        requestRawWithCallback(info, data, onResult) {
            if (typeof data === 'string') {
                if (!info.options.headers) {
                    info.options.headers = {}
                }
                info.options.headers['Content-Length'] = Buffer.byteLength(data, 'utf8')
            }
            let callbackCalled = false
            function handleResult(err, res) {
                if (!callbackCalled) {
                    callbackCalled = true
                    onResult(err, res)
                }
            }
            const req = info.httpModule.request(info.options, (msg) => {
                const res = new HttpClientResponse(msg)
                handleResult(undefined, res)
            })
            let socket
            req.on('socket', (sock) => {
                socket = sock
            })
            req.setTimeout(this._socketTimeout || 3 * 60000, () => {
                if (socket) {
                    socket.end()
                }
                handleResult(new Error(`Request timeout: ${info.options.path}`))
            })
            req.on('error', (err) => {
                handleResult(err)
            })
            if (data && typeof data === 'string') {
                req.write(data, 'utf8')
            }
            if (data && typeof data !== 'string') {
                data.on('close', () => {
                    req.end()
                })
                data.pipe(req)
            } else {
                req.end()
            }
        }
        getAgent(serverUrl) {
            const parsedUrl = new URL(serverUrl)
            return this._getAgent(parsedUrl)
        }
        getAgentDispatcher(serverUrl) {
            const parsedUrl = new URL(serverUrl)
            const proxyUrl = pm.getProxyUrl(parsedUrl)
            const useProxy = proxyUrl && proxyUrl.hostname
            if (!useProxy) {
                return
            }
            return this._getProxyAgentDispatcher(parsedUrl, proxyUrl)
        }
        _prepareRequest(method, requestUrl, headers) {
            const info = {}
            info.parsedUrl = requestUrl
            const usingSsl = info.parsedUrl.protocol === 'https:'
            info.httpModule = usingSsl ? https : http
            const defaultPort = usingSsl ? 443 : 80
            info.options = {}
            info.options.host = info.parsedUrl.hostname
            info.options.port = info.parsedUrl.port
                ? Number.parseInt(info.parsedUrl.port)
                : defaultPort
            info.options.path = (info.parsedUrl.pathname || '') + (info.parsedUrl.search || '')
            info.options.method = method
            info.options.headers = this._mergeHeaders(headers)
            if (this.userAgent != null) {
                info.options.headers['user-agent'] = this.userAgent
            }
            info.options.agent = this._getAgent(info.parsedUrl)
            if (this.handlers) {
                for (const handler of this.handlers) {
                    handler.prepareRequest(info.options)
                }
            }
            return info
        }
        _mergeHeaders(headers) {
            if (this.requestOptions && this.requestOptions.headers) {
                return Object.assign(
                    {},
                    lowercaseKeys(this.requestOptions.headers),
                    lowercaseKeys(headers || {})
                )
            }
            return lowercaseKeys(headers || {})
        }
        _getExistingOrDefaultHeader(additionalHeaders, header, _default) {
            let clientHeader
            if (this.requestOptions && this.requestOptions.headers) {
                clientHeader = lowercaseKeys(this.requestOptions.headers)[header]
            }
            return additionalHeaders[header] || clientHeader || _default
        }
        _getAgent(parsedUrl) {
            let agent
            const proxyUrl = pm.getProxyUrl(parsedUrl)
            const useProxy = proxyUrl && proxyUrl.hostname
            if (this._keepAlive && useProxy) {
                agent = this._proxyAgent
            }
            if (!useProxy) {
                agent = this._agent
            }
            if (agent) {
                return agent
            }
            const usingSsl = parsedUrl.protocol === 'https:'
            let maxSockets = 100
            if (this.requestOptions) {
                maxSockets = this.requestOptions.maxSockets || http.globalAgent.maxSockets
            }
            if (proxyUrl && proxyUrl.hostname) {
                const agentOptions = {
                    maxSockets,
                    keepAlive: this._keepAlive,
                    proxy: Object.assign(
                        Object.assign(
                            {},
                            (proxyUrl.username || proxyUrl.password) && {
                                proxyAuth: `${proxyUrl.username}:${proxyUrl.password}`,
                            }
                        ),
                        { host: proxyUrl.hostname, port: proxyUrl.port }
                    ),
                }
                let tunnelAgent
                const overHttps = proxyUrl.protocol === 'https:'
                if (usingSsl) {
                    tunnelAgent = overHttps ? tunnel.httpsOverHttps : tunnel.httpsOverHttp
                } else {
                    tunnelAgent = overHttps ? tunnel.httpOverHttps : tunnel.httpOverHttp
                }
                agent = tunnelAgent(agentOptions)
                this._proxyAgent = agent
            }
            if (!agent) {
                const options = { keepAlive: this._keepAlive, maxSockets }
                agent = usingSsl ? new https.Agent(options) : new http.Agent(options)
                this._agent = agent
            }
            if (usingSsl && this._ignoreSslError) {
                agent.options = Object.assign(agent.options || {}, {
                    rejectUnauthorized: false,
                })
            }
            return agent
        }
        _getProxyAgentDispatcher(parsedUrl, proxyUrl) {
            let proxyAgent
            if (this._keepAlive) {
                proxyAgent = this._proxyAgentDispatcher
            }
            if (proxyAgent) {
                return proxyAgent
            }
            const usingSsl = parsedUrl.protocol === 'https:'
            proxyAgent = new undici_1.ProxyAgent(
                Object.assign(
                    { uri: proxyUrl.href, pipelining: !this._keepAlive ? 0 : 1 },
                    (proxyUrl.username || proxyUrl.password) && {
                        token: `${proxyUrl.username}:${proxyUrl.password}`,
                    }
                )
            )
            this._proxyAgentDispatcher = proxyAgent
            if (usingSsl && this._ignoreSslError) {
                proxyAgent.options = Object.assign(proxyAgent.options.requestTls || {}, {
                    rejectUnauthorized: false,
                })
            }
            return proxyAgent
        }
        _performExponentialBackoff(retryNumber) {
            return __awaiter(this, undefined, undefined, function* () {
                retryNumber = Math.min(ExponentialBackoffCeiling, retryNumber)
                const ms = ExponentialBackoffTimeSlice * Math.pow(2, retryNumber)
                return new Promise((resolve) => setTimeout(() => resolve(), ms))
            })
        }
        _processResponse(res, options) {
            return __awaiter(this, undefined, undefined, function* () {
                return new Promise((resolve, reject) =>
                    __awaiter(this, undefined, undefined, function* () {
                        const statusCode = res.message.statusCode || 0
                        const response = {
                            statusCode,
                            result: null,
                            headers: {},
                        }
                        if (statusCode === HttpCodes.NotFound) {
                            resolve(response)
                        }
                        function dateTimeDeserializer(key, value) {
                            if (typeof value === 'string') {
                                const a = new Date(value)
                                if (!isNaN(a.valueOf())) {
                                    return a
                                }
                            }
                            return value
                        }
                        let obj
                        let contents
                        try {
                            contents = yield res.readBody()
                            if (contents && contents.length > 0) {
                                if (options && options.deserializeDates) {
                                    obj = JSON.parse(contents, dateTimeDeserializer)
                                } else {
                                    obj = JSON.parse(contents)
                                }
                                response.result = obj
                            }
                            response.headers = res.message.headers
                        } catch (err) {}
                        if (statusCode > 299) {
                            let msg
                            if (obj && obj.message) {
                                msg = obj.message
                            } else if (contents && contents.length > 0) {
                                msg = contents
                            } else {
                                msg = `Failed request: (${statusCode})`
                            }
                            const err = new HttpClientError(msg, statusCode)
                            err.result = response.result
                            reject(err)
                        } else {
                            resolve(response)
                        }
                    })
                )
            })
        }
    }
    exports.HttpClient = HttpClient
    var lowercaseKeys = (obj) =>
        Object.keys(obj).reduce((c, k) => ((c[k.toLowerCase()] = obj[k]), c), {})
})

// node_modules/@actions/http-client/lib/auth.js
var require_auth = __commonJS((exports) => {
    var __awaiter =
        (exports && exports.__awaiter) ||
        ((thisArg, _arguments, P, generator) => {
            function adopt(value) {
                return value instanceof P
                    ? value
                    : new P((resolve) => {
                          resolve(value)
                      })
            }
            return new (P || (P = Promise))((resolve, reject) => {
                function fulfilled(value) {
                    try {
                        step(generator.next(value))
                    } catch (e) {
                        reject(e)
                    }
                }
                function rejected(value) {
                    try {
                        step(generator['throw'](value))
                    } catch (e) {
                        reject(e)
                    }
                }
                function step(result) {
                    result.done
                        ? resolve(result.value)
                        : adopt(result.value).then(fulfilled, rejected)
                }
                step((generator = generator.apply(thisArg, _arguments || [])).next())
            })
        })
    Object.defineProperty(exports, '__esModule', { value: true })
    exports.PersonalAccessTokenCredentialHandler =
        exports.BearerCredentialHandler =
        exports.BasicCredentialHandler =
            undefined

    class BasicCredentialHandler {
        constructor(username, password) {
            this.username = username
            this.password = password
        }
        prepareRequest(options) {
            if (!options.headers) {
                throw Error('The request has no headers')
            }
            options.headers['Authorization'] =
                `Basic ${Buffer.from(`${this.username}:${this.password}`).toString('base64')}`
        }
        canHandleAuthentication() {
            return false
        }
        handleAuthentication() {
            return __awaiter(this, undefined, undefined, function* () {
                throw new Error('not implemented')
            })
        }
    }
    exports.BasicCredentialHandler = BasicCredentialHandler

    class BearerCredentialHandler {
        constructor(token) {
            this.token = token
        }
        prepareRequest(options) {
            if (!options.headers) {
                throw Error('The request has no headers')
            }
            options.headers['Authorization'] = `Bearer ${this.token}`
        }
        canHandleAuthentication() {
            return false
        }
        handleAuthentication() {
            return __awaiter(this, undefined, undefined, function* () {
                throw new Error('not implemented')
            })
        }
    }
    exports.BearerCredentialHandler = BearerCredentialHandler

    class PersonalAccessTokenCredentialHandler {
        constructor(token) {
            this.token = token
        }
        prepareRequest(options) {
            if (!options.headers) {
                throw Error('The request has no headers')
            }
            options.headers['Authorization'] =
                `Basic ${Buffer.from(`PAT:${this.token}`).toString('base64')}`
        }
        canHandleAuthentication() {
            return false
        }
        handleAuthentication() {
            return __awaiter(this, undefined, undefined, function* () {
                throw new Error('not implemented')
            })
        }
    }
    exports.PersonalAccessTokenCredentialHandler = PersonalAccessTokenCredentialHandler
})

// node_modules/@actions/core/lib/oidc-utils.js
var require_oidc_utils = __commonJS((exports) => {
    var __awaiter =
        (exports && exports.__awaiter) ||
        ((thisArg, _arguments, P, generator) => {
            function adopt(value) {
                return value instanceof P
                    ? value
                    : new P((resolve) => {
                          resolve(value)
                      })
            }
            return new (P || (P = Promise))((resolve, reject) => {
                function fulfilled(value) {
                    try {
                        step(generator.next(value))
                    } catch (e) {
                        reject(e)
                    }
                }
                function rejected(value) {
                    try {
                        step(generator['throw'](value))
                    } catch (e) {
                        reject(e)
                    }
                }
                function step(result) {
                    result.done
                        ? resolve(result.value)
                        : adopt(result.value).then(fulfilled, rejected)
                }
                step((generator = generator.apply(thisArg, _arguments || [])).next())
            })
        })
    Object.defineProperty(exports, '__esModule', { value: true })
    exports.OidcClient = undefined
    var http_client_1 = require_lib()
    var auth_1 = require_auth()
    var core_1 = require_core()

    class OidcClient {
        static createHttpClient(allowRetry = true, maxRetry = 10) {
            const requestOptions = {
                allowRetries: allowRetry,
                maxRetries: maxRetry,
            }
            return new http_client_1.HttpClient(
                'actions/oidc-client',
                [new auth_1.BearerCredentialHandler(OidcClient.getRequestToken())],
                requestOptions
            )
        }
        static getRequestToken() {
            const token = process.env['ACTIONS_ID_TOKEN_REQUEST_TOKEN']
            if (!token) {
                throw new Error('Unable to get ACTIONS_ID_TOKEN_REQUEST_TOKEN env variable')
            }
            return token
        }
        static getIDTokenUrl() {
            const runtimeUrl = process.env['ACTIONS_ID_TOKEN_REQUEST_URL']
            if (!runtimeUrl) {
                throw new Error('Unable to get ACTIONS_ID_TOKEN_REQUEST_URL env variable')
            }
            return runtimeUrl
        }
        static getCall(id_token_url) {
            var _a
            return __awaiter(this, undefined, undefined, function* () {
                const httpclient = OidcClient.createHttpClient()
                const res = yield httpclient.getJson(id_token_url).catch((error) => {
                    throw new Error(`Failed to get ID Token. \n 
        Error Code : ${error.statusCode}\n 
        Error Message: ${error.message}`)
                })
                const id_token =
                    (_a = res.result) === null || _a === undefined ? undefined : _a.value
                if (!id_token) {
                    throw new Error('Response json body do not have ID Token field')
                }
                return id_token
            })
        }
        static getIDToken(audience) {
            return __awaiter(this, undefined, undefined, function* () {
                try {
                    let id_token_url = OidcClient.getIDTokenUrl()
                    if (audience) {
                        const encodedAudience = encodeURIComponent(audience)
                        id_token_url = `${id_token_url}&audience=${encodedAudience}`
                    }
                    core_1.debug(`ID token url is ${id_token_url}`)
                    const id_token = yield OidcClient.getCall(id_token_url)
                    core_1.setSecret(id_token)
                    return id_token
                } catch (error) {
                    throw new Error(`Error message: ${error.message}`)
                }
            })
        }
    }
    exports.OidcClient = OidcClient
})

// node_modules/@actions/core/lib/summary.js
var require_summary = __commonJS((exports) => {
    var __awaiter =
        (exports && exports.__awaiter) ||
        ((thisArg, _arguments, P, generator) => {
            function adopt(value) {
                return value instanceof P
                    ? value
                    : new P((resolve) => {
                          resolve(value)
                      })
            }
            return new (P || (P = Promise))((resolve, reject) => {
                function fulfilled(value) {
                    try {
                        step(generator.next(value))
                    } catch (e) {
                        reject(e)
                    }
                }
                function rejected(value) {
                    try {
                        step(generator['throw'](value))
                    } catch (e) {
                        reject(e)
                    }
                }
                function step(result) {
                    result.done
                        ? resolve(result.value)
                        : adopt(result.value).then(fulfilled, rejected)
                }
                step((generator = generator.apply(thisArg, _arguments || [])).next())
            })
        })
    Object.defineProperty(exports, '__esModule', { value: true })
    exports.summary =
        exports.markdownSummary =
        exports.SUMMARY_DOCS_URL =
        exports.SUMMARY_ENV_VAR =
            undefined
    var os_1 = import.meta.require('os')
    var fs_1 = import.meta.require('fs')
    var { access, appendFile, writeFile } = fs_1.promises
    exports.SUMMARY_ENV_VAR = 'GITHUB_STEP_SUMMARY'
    exports.SUMMARY_DOCS_URL =
        'https://docs.github.com/actions/using-workflows/workflow-commands-for-github-actions#adding-a-job-summary'

    class Summary {
        constructor() {
            this._buffer = ''
        }
        filePath() {
            return __awaiter(this, undefined, undefined, function* () {
                if (this._filePath) {
                    return this._filePath
                }
                const pathFromEnv = process.env[exports.SUMMARY_ENV_VAR]
                if (!pathFromEnv) {
                    throw new Error(
                        `Unable to find environment variable for \$${exports.SUMMARY_ENV_VAR}. Check if your runtime environment supports job summaries.`
                    )
                }
                try {
                    yield access(pathFromEnv, fs_1.constants.R_OK | fs_1.constants.W_OK)
                } catch (_a) {
                    throw new Error(
                        `Unable to access summary file: '${pathFromEnv}'. Check if the file has correct read/write permissions.`
                    )
                }
                this._filePath = pathFromEnv
                return this._filePath
            })
        }
        wrap(tag, content, attrs = {}) {
            const htmlAttrs = Object.entries(attrs)
                .map(([key, value]) => ` ${key}="${value}"`)
                .join('')
            if (!content) {
                return `<${tag}${htmlAttrs}>`
            }
            return `<${tag}${htmlAttrs}>${content}</${tag}>`
        }
        write(options) {
            return __awaiter(this, undefined, undefined, function* () {
                const overwrite = !!(options === null || options === undefined
                    ? undefined
                    : options.overwrite)
                const filePath = yield this.filePath()
                const writeFunc = overwrite ? writeFile : appendFile
                yield writeFunc(filePath, this._buffer, { encoding: 'utf8' })
                return this.emptyBuffer()
            })
        }
        clear() {
            return __awaiter(this, undefined, undefined, function* () {
                return this.emptyBuffer().write({ overwrite: true })
            })
        }
        stringify() {
            return this._buffer
        }
        isEmptyBuffer() {
            return this._buffer.length === 0
        }
        emptyBuffer() {
            this._buffer = ''
            return this
        }
        addRaw(text, addEOL = false) {
            this._buffer += text
            return addEOL ? this.addEOL() : this
        }
        addEOL() {
            return this.addRaw(os_1.EOL)
        }
        addCodeBlock(code, lang) {
            const attrs = Object.assign({}, lang && { lang })
            const element = this.wrap('pre', this.wrap('code', code), attrs)
            return this.addRaw(element).addEOL()
        }
        addList(items, ordered = false) {
            const tag = ordered ? 'ol' : 'ul'
            const listItems = items.map((item) => this.wrap('li', item)).join('')
            const element = this.wrap(tag, listItems)
            return this.addRaw(element).addEOL()
        }
        addTable(rows) {
            const tableBody = rows
                .map((row) => {
                    const cells = row
                        .map((cell) => {
                            if (typeof cell === 'string') {
                                return this.wrap('td', cell)
                            }
                            const { header, data, colspan, rowspan } = cell
                            const tag = header ? 'th' : 'td'
                            const attrs = Object.assign(
                                Object.assign({}, colspan && { colspan }),
                                rowspan && { rowspan }
                            )
                            return this.wrap(tag, data, attrs)
                        })
                        .join('')
                    return this.wrap('tr', cells)
                })
                .join('')
            const element = this.wrap('table', tableBody)
            return this.addRaw(element).addEOL()
        }
        addDetails(label, content) {
            const element = this.wrap('details', this.wrap('summary', label) + content)
            return this.addRaw(element).addEOL()
        }
        addImage(src, alt, options) {
            const { width, height } = options || {}
            const attrs = Object.assign(Object.assign({}, width && { width }), height && { height })
            const element = this.wrap('img', null, Object.assign({ src, alt }, attrs))
            return this.addRaw(element).addEOL()
        }
        addHeading(text, level) {
            const tag = `h${level}`
            const allowedTag = ['h1', 'h2', 'h3', 'h4', 'h5', 'h6'].includes(tag) ? tag : 'h1'
            const element = this.wrap(allowedTag, text)
            return this.addRaw(element).addEOL()
        }
        addSeparator() {
            const element = this.wrap('hr', null)
            return this.addRaw(element).addEOL()
        }
        addBreak() {
            const element = this.wrap('br', null)
            return this.addRaw(element).addEOL()
        }
        addQuote(text, cite) {
            const attrs = Object.assign({}, cite && { cite })
            const element = this.wrap('blockquote', text, attrs)
            return this.addRaw(element).addEOL()
        }
        addLink(text, href) {
            const element = this.wrap('a', text, { href })
            return this.addRaw(element).addEOL()
        }
    }
    var _summary = new Summary()
    exports.markdownSummary = _summary
    exports.summary = _summary
})

// node_modules/@actions/core/lib/path-utils.js
var require_path_utils = __commonJS((exports) => {
    var toPosixPath = (pth) => pth.replace(/[\\]/g, '/')
    var toWin32Path = (pth) => pth.replace(/[/]/g, '\\')
    var toPlatformPath = (pth) => pth.replace(/[/\\]/g, path.sep)
    var __createBinding =
        (exports && exports.__createBinding) ||
        (Object.create
            ? (o, m, k, k2) => {
                  if (k2 === undefined) k2 = k
                  Object.defineProperty(o, k2, { enumerable: true, get: () => m[k] })
              }
            : (o, m, k, k2) => {
                  if (k2 === undefined) k2 = k
                  o[k2] = m[k]
              })
    var __setModuleDefault =
        (exports && exports.__setModuleDefault) ||
        (Object.create
            ? (o, v) => {
                  Object.defineProperty(o, 'default', { enumerable: true, value: v })
              }
            : (o, v) => {
                  o['default'] = v
              })
    var __importStar =
        (exports && exports.__importStar) ||
        ((mod) => {
            if (mod && mod.__esModule) return mod
            var result = {}
            if (mod != null) {
                for (var k in mod)
                    if (k !== 'default' && Object.hasOwnProperty.call(mod, k))
                        __createBinding(result, mod, k)
            }
            __setModuleDefault(result, mod)
            return result
        })
    Object.defineProperty(exports, '__esModule', { value: true })
    exports.toPlatformPath = exports.toWin32Path = exports.toPosixPath = undefined
    var path = __importStar(import.meta.require('path'))
    exports.toPosixPath = toPosixPath
    exports.toWin32Path = toWin32Path
    exports.toPlatformPath = toPlatformPath
})

// node_modules/@actions/core/lib/core.js
var require_core = __commonJS((exports) => {
    var exportVariable = (name, val) => {
        const convertedVal = utils_1.toCommandValue(val)
        process.env[name] = convertedVal
        const filePath = process.env['GITHUB_ENV'] || ''
        if (filePath) {
            return file_command_1.issueFileCommand(
                'ENV',
                file_command_1.prepareKeyValueMessage(name, val)
            )
        }
        command_1.issueCommand('set-env', { name }, convertedVal)
    }
    var setSecret = (secret) => {
        command_1.issueCommand('add-mask', {}, secret)
    }
    var addPath = (inputPath) => {
        const filePath = process.env['GITHUB_PATH'] || ''
        if (filePath) {
            file_command_1.issueFileCommand('PATH', inputPath)
        } else {
            command_1.issueCommand('add-path', {}, inputPath)
        }
        process.env['PATH'] =
            `${inputPath}${path.delimiter}${'/Users/chris.bennett/Code/workbench/gh-action-template/node_modules/.bin:/Users/chris.bennett/Code/workbench/gh-action-template/node_modules/.bin:/Users/chris.bennett/Code/workbench/node_modules/.bin:/Users/chris.bennett/Code/node_modules/.bin:/Users/chris.bennett/node_modules/.bin:/Users/node_modules/.bin:/node_modules/.bin:/Users/chris.bennett/.yarn/bin:/Users/chris.bennett/.config/yarn/global/node_modules/.bin:/Users/chris.bennett/.console-ninja/.bin:/Users/chris.bennett/.local/state/fnm_multishells/37519_1720458018646/bin:/Users/chris.bennett/Library/Application Support/fnm:/usr/bin/python3:/Users/chris.bennett/.bun/bin:/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/bin:/System/Cryptexes/App/usr/bin:/usr/bin:/bin:/usr/sbin:/sbin:/var/run/com.apple.security.cryptexd/codex.system/bootstrap/usr/local/bin:/var/run/com.apple.security.cryptexd/codex.system/bootstrap/usr/bin:/var/run/com.apple.security.cryptexd/codex.system/bootstrap/usr/appleinternal/bin:/usr/local/go/bin:/Library/Frameworks/Mono.framework/Versions/Current/Commands:/usr/local/munki:/Users/chris.bennett/.yarn/bin:/Users/chris.bennett/.config/yarn/global/node_modules/.bin:/Users/chris.bennett/.console-ninja/.bin:/Users/chris.bennett/.local/state/fnm_multishells/35100_1720457917118/bin:/Users/chris.bennett/Library/Application Support/fnm:/usr/bin/python3:/Users/chris.bennett/.bun/bin:/opt/homebrew/bin:/opt/homebrew/sbin:/Users/chris.bennett/.local/state/fnm_multishells/31216_1720457742026/bin:/Users/chris.bennett/.local/state/fnm_multishells/2970_1720452807865/bin:/Users/chris.bennett/.vscode/extensions/ms-python.python-2024.8.1/python_files/deactivate/zsh:/Users/chris.bennett/Code/workbench/strava-import/.venv/bin:/Users/chris.bennett/.local/state/fnm_multishells/24300_1720363473450/bin:/Users/chris.bennett/.local/state/fnm_multishells/23694_1720363313520/bin:/Users/chris.bennett/Library/pnpm:/Users/chris.bennett/.cargo/bin:/Users/chris.bennett/.local/bin:/Users/chris.bennett/.orbstack/bin:/Applications/Visual Studio Code.app/Contents/Resources/app/bin:/Users/chris.bennett/.local/bin:/Users/chris.bennett/.orbstack/bin:/Users/chris.bennett/.local/bin:/Applications/Visual Studio Code.app/Contents/Resources/app/bin'}`
    }
    var getInput = (name, options) => {
        const val = process.env[`INPUT_${name.replace(/ /g, '_').toUpperCase()}`] || ''
        if (options && options.required && !val) {
            throw new Error(`Input required and not supplied: ${name}`)
        }
        if (options && options.trimWhitespace === false) {
            return val
        }
        return val.trim()
    }
    var getMultilineInput = (name, options) => {
        const inputs = getInput(name, options)
            .split('\n')
            .filter((x) => x !== '')
        if (options && options.trimWhitespace === false) {
            return inputs
        }
        return inputs.map((input) => input.trim())
    }
    var getBooleanInput = (name, options) => {
        const trueValue = ['true', 'True', 'TRUE']
        const falseValue = ['false', 'False', 'FALSE']
        const val = getInput(name, options)
        if (trueValue.includes(val)) return true
        if (falseValue.includes(val)) return false
        throw new TypeError(
            `Input does not meet YAML 1.2 "Core Schema" specification: ${name}\n` +
                `Support boolean input list: \`true | True | TRUE | false | False | FALSE\``
        )
    }
    var setOutput = (name, value) => {
        const filePath = process.env['GITHUB_OUTPUT'] || ''
        if (filePath) {
            return file_command_1.issueFileCommand(
                'OUTPUT',
                file_command_1.prepareKeyValueMessage(name, value)
            )
        }
        process.stdout.write(os.EOL)
        command_1.issueCommand('set-output', { name }, utils_1.toCommandValue(value))
    }
    var setCommandEcho = (enabled) => {
        command_1.issue('echo', enabled ? 'on' : 'off')
    }
    var setFailed = (message) => {
        process.exitCode = ExitCode.Failure
        error(message)
    }
    var isDebug = () => process.env['RUNNER_DEBUG'] === '1'
    var debug = (message) => {
        command_1.issueCommand('debug', {}, message)
    }
    var error = (message, properties = {}) => {
        command_1.issueCommand(
            'error',
            utils_1.toCommandProperties(properties),
            message instanceof Error ? message.toString() : message
        )
    }
    var warning = (message, properties = {}) => {
        command_1.issueCommand(
            'warning',
            utils_1.toCommandProperties(properties),
            message instanceof Error ? message.toString() : message
        )
    }
    var notice = (message, properties = {}) => {
        command_1.issueCommand(
            'notice',
            utils_1.toCommandProperties(properties),
            message instanceof Error ? message.toString() : message
        )
    }
    var info = (message) => {
        process.stdout.write(message + os.EOL)
    }
    var startGroup = (name) => {
        command_1.issue('group', name)
    }
    var endGroup = () => {
        command_1.issue('endgroup')
    }
    var group = function (name, fn) {
        return __awaiter(this, undefined, undefined, function* () {
            startGroup(name)
            let result
            try {
                result = yield fn()
            } finally {
                endGroup()
            }
            return result
        })
    }
    var saveState = (name, value) => {
        const filePath = process.env['GITHUB_STATE'] || ''
        if (filePath) {
            return file_command_1.issueFileCommand(
                'STATE',
                file_command_1.prepareKeyValueMessage(name, value)
            )
        }
        command_1.issueCommand('save-state', { name }, utils_1.toCommandValue(value))
    }
    var getState = (name) => process.env[`STATE_${name}`] || ''
    var getIDToken = function (aud) {
        return __awaiter(this, undefined, undefined, function* () {
            return yield oidc_utils_1.OidcClient.getIDToken(aud)
        })
    }
    var __createBinding =
        (exports && exports.__createBinding) ||
        (Object.create
            ? (o, m, k, k2) => {
                  if (k2 === undefined) k2 = k
                  Object.defineProperty(o, k2, { enumerable: true, get: () => m[k] })
              }
            : (o, m, k, k2) => {
                  if (k2 === undefined) k2 = k
                  o[k2] = m[k]
              })
    var __setModuleDefault =
        (exports && exports.__setModuleDefault) ||
        (Object.create
            ? (o, v) => {
                  Object.defineProperty(o, 'default', { enumerable: true, value: v })
              }
            : (o, v) => {
                  o['default'] = v
              })
    var __importStar =
        (exports && exports.__importStar) ||
        ((mod) => {
            if (mod && mod.__esModule) return mod
            var result = {}
            if (mod != null) {
                for (var k in mod)
                    if (k !== 'default' && Object.hasOwnProperty.call(mod, k))
                        __createBinding(result, mod, k)
            }
            __setModuleDefault(result, mod)
            return result
        })
    var __awaiter =
        (exports && exports.__awaiter) ||
        ((thisArg, _arguments, P, generator) => {
            function adopt(value) {
                return value instanceof P
                    ? value
                    : new P((resolve) => {
                          resolve(value)
                      })
            }
            return new (P || (P = Promise))((resolve, reject) => {
                function fulfilled(value) {
                    try {
                        step(generator.next(value))
                    } catch (e) {
                        reject(e)
                    }
                }
                function rejected(value) {
                    try {
                        step(generator['throw'](value))
                    } catch (e) {
                        reject(e)
                    }
                }
                function step(result) {
                    result.done
                        ? resolve(result.value)
                        : adopt(result.value).then(fulfilled, rejected)
                }
                step((generator = generator.apply(thisArg, _arguments || [])).next())
            })
        })
    Object.defineProperty(exports, '__esModule', { value: true })
    exports.getIDToken =
        exports.getState =
        exports.saveState =
        exports.group =
        exports.endGroup =
        exports.startGroup =
        exports.info =
        exports.notice =
        exports.warning =
        exports.error =
        exports.debug =
        exports.isDebug =
        exports.setFailed =
        exports.setCommandEcho =
        exports.setOutput =
        exports.getBooleanInput =
        exports.getMultilineInput =
        exports.getInput =
        exports.addPath =
        exports.setSecret =
        exports.exportVariable =
        exports.ExitCode =
            undefined
    var command_1 = require_command()
    var file_command_1 = require_file_command()
    var utils_1 = require_utils()
    var os = __importStar(import.meta.require('os'))
    var path = __importStar(import.meta.require('path'))
    var oidc_utils_1 = require_oidc_utils()
    var ExitCode
    ;((ExitCode2) => {
        ExitCode2[(ExitCode2['Success'] = 0)] = 'Success'
        ExitCode2[(ExitCode2['Failure'] = 1)] = 'Failure'
    })((ExitCode = exports.ExitCode || (exports.ExitCode = {})))
    exports.exportVariable = exportVariable
    exports.setSecret = setSecret
    exports.addPath = addPath
    exports.getInput = getInput
    exports.getMultilineInput = getMultilineInput
    exports.getBooleanInput = getBooleanInput
    exports.setOutput = setOutput
    exports.setCommandEcho = setCommandEcho
    exports.setFailed = setFailed
    exports.isDebug = isDebug
    exports.debug = debug
    exports.error = error
    exports.warning = warning
    exports.notice = notice
    exports.info = info
    exports.startGroup = startGroup
    exports.endGroup = endGroup
    exports.group = group
    exports.saveState = saveState
    exports.getState = getState
    exports.getIDToken = getIDToken
    var summary_1 = require_summary()
    Object.defineProperty(exports, 'summary', { enumerable: true, get: () => summary_1.summary })
    var summary_2 = require_summary()
    Object.defineProperty(exports, 'markdownSummary', {
        enumerable: true,
        get: () => summary_2.markdownSummary,
    })
    var path_utils_1 = require_path_utils()
    Object.defineProperty(exports, 'toPosixPath', {
        enumerable: true,
        get: () => path_utils_1.toPosixPath,
    })
    Object.defineProperty(exports, 'toWin32Path', {
        enumerable: true,
        get: () => path_utils_1.toWin32Path,
    })
    Object.defineProperty(exports, 'toPlatformPath', {
        enumerable: true,
        get: () => path_utils_1.toPlatformPath,
    })
})

// node_modules/@actions/github/lib/context.js
var require_context = __commonJS((exports) => {
    Object.defineProperty(exports, '__esModule', { value: true })
    exports.Context = undefined
    var fs_1 = import.meta.require('fs')
    var os_1 = import.meta.require('os')

    class Context {
        constructor() {
            var _a, _b, _c
            this.payload = {}
            if (process.env.GITHUB_EVENT_PATH) {
                if ((0, fs_1.existsSync)(process.env.GITHUB_EVENT_PATH)) {
                    this.payload = JSON.parse(
                        (0, fs_1.readFileSync)(process.env.GITHUB_EVENT_PATH, { encoding: 'utf8' })
                    )
                } else {
                    const path = process.env.GITHUB_EVENT_PATH
                    process.stdout.write(`GITHUB_EVENT_PATH ${path} does not exist${os_1.EOL}`)
                }
            }
            this.eventName = process.env.GITHUB_EVENT_NAME
            this.sha = process.env.GITHUB_SHA
            this.ref = process.env.GITHUB_REF
            this.workflow = process.env.GITHUB_WORKFLOW
            this.action = process.env.GITHUB_ACTION
            this.actor = process.env.GITHUB_ACTOR
            this.job = process.env.GITHUB_JOB
            this.runNumber = Number.parseInt(process.env.GITHUB_RUN_NUMBER, 10)
            this.runId = Number.parseInt(process.env.GITHUB_RUN_ID, 10)
            this.apiUrl =
                (_a = process.env.GITHUB_API_URL) !== null && _a !== undefined
                    ? _a
                    : `https://api.github.com`
            this.serverUrl =
                (_b = process.env.GITHUB_SERVER_URL) !== null && _b !== undefined
                    ? _b
                    : `https://github.com`
            this.graphqlUrl =
                (_c = process.env.GITHUB_GRAPHQL_URL) !== null && _c !== undefined
                    ? _c
                    : `https://api.github.com/graphql`
        }
        get issue() {
            const payload = this.payload
            return Object.assign(Object.assign({}, this.repo), {
                number: (payload.issue || payload.pull_request || payload).number,
            })
        }
        get repo() {
            if (process.env.GITHUB_REPOSITORY) {
                const [owner, repo] = process.env.GITHUB_REPOSITORY.split('/')
                return { owner, repo }
            }
            if (this.payload.repository) {
                return {
                    owner: this.payload.repository.owner.login,
                    repo: this.payload.repository.name,
                }
            }
            throw new Error(
                "context.repo requires a GITHUB_REPOSITORY environment variable like 'owner/repo'"
            )
        }
    }
    exports.Context = Context
})

// node_modules/@actions/github/lib/internal/utils.js
var require_utils2 = __commonJS((exports) => {
    var getAuthString = (token, options) => {
        if (!token && !options.auth) {
            throw new Error('Parameter token or opts.auth is required')
        } else if (token && options.auth) {
            throw new Error('Parameters token and opts.auth may not both be specified')
        }
        return typeof options.auth === 'string' ? options.auth : `token ${token}`
    }
    var getProxyAgent = (destinationUrl) => {
        const hc = new httpClient.HttpClient()
        return hc.getAgent(destinationUrl)
    }
    var getProxyAgentDispatcher = (destinationUrl) => {
        const hc = new httpClient.HttpClient()
        return hc.getAgentDispatcher(destinationUrl)
    }
    var getProxyFetch = function (destinationUrl) {
        const httpDispatcher = getProxyAgentDispatcher(destinationUrl)
        const proxyFetch = (url, opts) =>
            __awaiter(this, undefined, undefined, function* () {
                return (0, undici_1.fetch)(
                    url,
                    Object.assign(Object.assign({}, opts), { dispatcher: httpDispatcher })
                )
            })
        return proxyFetch
    }
    var getApiBaseUrl = () => process.env['GITHUB_API_URL'] || 'https://api.github.com'
    var __createBinding =
        (exports && exports.__createBinding) ||
        (Object.create
            ? (o, m, k, k2) => {
                  if (k2 === undefined) k2 = k
                  var desc = Object.getOwnPropertyDescriptor(m, k)
                  if (
                      !desc ||
                      ('get' in desc ? !m.__esModule : desc.writable || desc.configurable)
                  ) {
                      desc = { enumerable: true, get: () => m[k] }
                  }
                  Object.defineProperty(o, k2, desc)
              }
            : (o, m, k, k2) => {
                  if (k2 === undefined) k2 = k
                  o[k2] = m[k]
              })
    var __setModuleDefault =
        (exports && exports.__setModuleDefault) ||
        (Object.create
            ? (o, v) => {
                  Object.defineProperty(o, 'default', { enumerable: true, value: v })
              }
            : (o, v) => {
                  o['default'] = v
              })
    var __importStar =
        (exports && exports.__importStar) ||
        ((mod) => {
            if (mod && mod.__esModule) return mod
            var result = {}
            if (mod != null) {
                for (var k in mod)
                    if (k !== 'default' && Object.prototype.hasOwnProperty.call(mod, k))
                        __createBinding(result, mod, k)
            }
            __setModuleDefault(result, mod)
            return result
        })
    var __awaiter =
        (exports && exports.__awaiter) ||
        ((thisArg, _arguments, P, generator) => {
            function adopt(value) {
                return value instanceof P
                    ? value
                    : new P((resolve) => {
                          resolve(value)
                      })
            }
            return new (P || (P = Promise))((resolve, reject) => {
                function fulfilled(value) {
                    try {
                        step(generator.next(value))
                    } catch (e) {
                        reject(e)
                    }
                }
                function rejected(value) {
                    try {
                        step(generator['throw'](value))
                    } catch (e) {
                        reject(e)
                    }
                }
                function step(result) {
                    result.done
                        ? resolve(result.value)
                        : adopt(result.value).then(fulfilled, rejected)
                }
                step((generator = generator.apply(thisArg, _arguments || [])).next())
            })
        })
    Object.defineProperty(exports, '__esModule', { value: true })
    exports.getApiBaseUrl =
        exports.getProxyFetch =
        exports.getProxyAgentDispatcher =
        exports.getProxyAgent =
        exports.getAuthString =
            undefined
    var httpClient = __importStar(require_lib())
    var undici_1 = import.meta.require('undici')
    exports.getAuthString = getAuthString
    exports.getProxyAgent = getProxyAgent
    exports.getProxyAgentDispatcher = getProxyAgentDispatcher
    exports.getProxyFetch = getProxyFetch
    exports.getApiBaseUrl = getApiBaseUrl
})

// node_modules/universal-user-agent/dist-node/index.js
var require_dist_node = __commonJS((exports) => {
    var getUserAgent = () => {
        if (typeof navigator === 'object' && 'userAgent' in navigator) {
            return navigator.userAgent
        }
        if (typeof process === 'object' && process.version !== undefined) {
            return `Node.js/${process.version.substr(1)} (${process.platform}; ${process.arch})`
        }
        return '<environment undetectable>'
    }
    Object.defineProperty(exports, '__esModule', { value: true })
    exports.getUserAgent = getUserAgent
})

// node_modules/before-after-hook/lib/register.js
var require_register = __commonJS((exports, module) => {
    var register = (state, name, method, options) => {
        if (typeof method !== 'function') {
            throw new Error('method for before hook must be a function')
        }
        if (!options) {
            options = {}
        }
        if (Array.isArray(name)) {
            return name
                .reverse()
                .reduce(
                    (callback, name2) => register.bind(null, state, name2, callback, options),
                    method
                )()
        }
        return Promise.resolve().then(() => {
            if (!state.registry[name]) {
                return method(options)
            }
            return state.registry[name].reduce(
                (method2, registered) => registered.hook.bind(null, method2, options),
                method
            )()
        })
    }
    module.exports = register
})

// node_modules/before-after-hook/lib/add.js
var require_add = __commonJS((exports, module) => {
    var addHook = (state, kind, name, hook) => {
        var orig = hook
        if (!state.registry[name]) {
            state.registry[name] = []
        }
        if (kind === 'before') {
            hook = (method, options) =>
                Promise.resolve().then(orig.bind(null, options)).then(method.bind(null, options))
        }
        if (kind === 'after') {
            hook = (method, options) => {
                var result
                return Promise.resolve()
                    .then(method.bind(null, options))
                    .then((result_) => {
                        result = result_
                        return orig(result, options)
                    })
                    .then(() => result)
            }
        }
        if (kind === 'error') {
            hook = (method, options) =>
                Promise.resolve()
                    .then(method.bind(null, options))
                    .catch((error) => orig(error, options))
        }
        state.registry[name].push({
            hook,
            orig,
        })
    }
    module.exports = addHook
})

// node_modules/before-after-hook/lib/remove.js
var require_remove = __commonJS((exports, module) => {
    var removeHook = (state, name, method) => {
        if (!state.registry[name]) {
            return
        }
        var index = state.registry[name].map((registered) => registered.orig).indexOf(method)
        if (index === -1) {
            return
        }
        state.registry[name].splice(index, 1)
    }
    module.exports = removeHook
})

// node_modules/before-after-hook/index.js
var require_before_after_hook = __commonJS((exports, module) => {
    var bindApi = (hook, state, name) => {
        var removeHookRef = bindable(removeHook, null).apply(null, name ? [state, name] : [state])
        hook.api = { remove: removeHookRef }
        hook.remove = removeHookRef
        ;['before', 'error', 'after', 'wrap'].forEach((kind) => {
            var args = name ? [state, kind, name] : [state, kind]
            hook[kind] = hook.api[kind] = bindable(addHook, null).apply(null, args)
        })
    }
    var HookSingular = () => {
        var singularHookName = 'h'
        var singularHookState = {
            registry: {},
        }
        var singularHook = register.bind(null, singularHookState, singularHookName)
        bindApi(singularHook, singularHookState, singularHookName)
        return singularHook
    }
    var HookCollection = () => {
        var state = {
            registry: {},
        }
        var hook = register.bind(null, state)
        bindApi(hook, state)
        return hook
    }
    var Hook = () => {
        if (!collectionHookDeprecationMessageDisplayed) {
            console.warn(
                '[before-after-hook]: "Hook()" repurposing warning, use "Hook.Collection()". Read more: https://git.io/upgrade-before-after-hook-to-1.4'
            )
            collectionHookDeprecationMessageDisplayed = true
        }
        return HookCollection()
    }
    var register = require_register()
    var addHook = require_add()
    var removeHook = require_remove()
    var bind = Function.bind
    var bindable = bind.bind(bind)
    var collectionHookDeprecationMessageDisplayed = false
    Hook.Singular = HookSingular.bind()
    Hook.Collection = HookCollection.bind()
    module.exports = Hook
    module.exports.Hook = Hook
    module.exports.Singular = Hook.Singular
    module.exports.Collection = Hook.Collection
})

// node_modules/@octokit/endpoint/dist-node/index.js
var require_dist_node2 = __commonJS((exports, module) => {
    var lowercaseKeys = (object) => {
        if (!object) {
            return {}
        }
        return Object.keys(object).reduce((newObj, key) => {
            newObj[key.toLowerCase()] = object[key]
            return newObj
        }, {})
    }
    var isPlainObject = (value) => {
        if (typeof value !== 'object' || value === null) return false
        if (Object.prototype.toString.call(value) !== '[object Object]') return false
        const proto = Object.getPrototypeOf(value)
        if (proto === null) return true
        const Ctor = Object.prototype.hasOwnProperty.call(proto, 'constructor') && proto.constructor
        return (
            typeof Ctor === 'function' &&
            Ctor instanceof Ctor &&
            Function.prototype.call(Ctor) === Function.prototype.call(value)
        )
    }
    var mergeDeep = (defaults, options) => {
        const result = Object.assign({}, defaults)
        Object.keys(options).forEach((key) => {
            if (isPlainObject(options[key])) {
                if (!(key in defaults)) Object.assign(result, { [key]: options[key] })
                else result[key] = mergeDeep(defaults[key], options[key])
            } else {
                Object.assign(result, { [key]: options[key] })
            }
        })
        return result
    }
    var removeUndefinedProperties = (obj) => {
        for (const key in obj) {
            if (obj[key] === undefined) {
                delete obj[key]
            }
        }
        return obj
    }
    var merge = (defaults, route, options) => {
        if (typeof route === 'string') {
            const [method, url] = route.split(' ')
            options = Object.assign(url ? { method, url } : { url: method }, options)
        } else {
            options = Object.assign({}, route)
        }
        options.headers = lowercaseKeys(options.headers)
        removeUndefinedProperties(options)
        removeUndefinedProperties(options.headers)
        const mergedOptions = mergeDeep(defaults || {}, options)
        if (options.url === '/graphql') {
            if (defaults && defaults.mediaType.previews?.length) {
                mergedOptions.mediaType.previews = defaults.mediaType.previews
                    .filter((preview) => !mergedOptions.mediaType.previews.includes(preview))
                    .concat(mergedOptions.mediaType.previews)
            }
            mergedOptions.mediaType.previews = (mergedOptions.mediaType.previews || []).map(
                (preview) => preview.replace(/-preview/, '')
            )
        }
        return mergedOptions
    }
    var addQueryParameters = (url, parameters) => {
        const separator = /\?/.test(url) ? '&' : '?'
        const names = Object.keys(parameters)
        if (names.length === 0) {
            return url
        }
        return (
            url +
            separator +
            names
                .map((name) => {
                    if (name === 'q') {
                        return 'q=' + parameters.q.split('+').map(encodeURIComponent).join('+')
                    }
                    return `${name}=${encodeURIComponent(parameters[name])}`
                })
                .join('&')
        )
    }
    var removeNonChars = (variableName) => variableName.replace(/^\W+|\W+$/g, '').split(/,/)
    var extractUrlVariableNames = (url) => {
        const matches = url.match(urlVariableRegex)
        if (!matches) {
            return []
        }
        return matches.map(removeNonChars).reduce((a, b) => a.concat(b), [])
    }
    var omit = (object, keysToOmit) => {
        const result = { __proto__: null }
        for (const key of Object.keys(object)) {
            if (keysToOmit.indexOf(key) === -1) {
                result[key] = object[key]
            }
        }
        return result
    }
    var encodeReserved = (str) =>
        str
            .split(/(%[0-9A-Fa-f]{2})/g)
            .map((part) => {
                if (!/%[0-9A-Fa-f]/.test(part)) {
                    part = encodeURI(part).replace(/%5B/g, '[').replace(/%5D/g, ']')
                }
                return part
            })
            .join('')
    var encodeUnreserved = (str) =>
        encodeURIComponent(str).replace(
            /[!'()*]/g,
            (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase()
        )
    var encodeValue = (operator, value, key) => {
        value =
            operator === '+' || operator === '#' ? encodeReserved(value) : encodeUnreserved(value)
        if (key) {
            return encodeUnreserved(key) + '=' + value
        } else {
            return value
        }
    }
    var isDefined = (value) => value !== undefined && value !== null
    var isKeyOperator = (operator) => operator === ';' || operator === '&' || operator === '?'
    var getValues = (context, operator, key, modifier) => {
        var value = context[key],
            result = []
        if (isDefined(value) && value !== '') {
            if (
                typeof value === 'string' ||
                typeof value === 'number' ||
                typeof value === 'boolean'
            ) {
                value = value.toString()
                if (modifier && modifier !== '*') {
                    value = value.substring(0, Number.parseInt(modifier, 10))
                }
                result.push(encodeValue(operator, value, isKeyOperator(operator) ? key : ''))
            } else {
                if (modifier === '*') {
                    if (Array.isArray(value)) {
                        value.filter(isDefined).forEach((value2) => {
                            result.push(
                                encodeValue(operator, value2, isKeyOperator(operator) ? key : '')
                            )
                        })
                    } else {
                        Object.keys(value).forEach((k) => {
                            if (isDefined(value[k])) {
                                result.push(encodeValue(operator, value[k], k))
                            }
                        })
                    }
                } else {
                    const tmp = []
                    if (Array.isArray(value)) {
                        value.filter(isDefined).forEach((value2) => {
                            tmp.push(encodeValue(operator, value2))
                        })
                    } else {
                        Object.keys(value).forEach((k) => {
                            if (isDefined(value[k])) {
                                tmp.push(encodeUnreserved(k))
                                tmp.push(encodeValue(operator, value[k].toString()))
                            }
                        })
                    }
                    if (isKeyOperator(operator)) {
                        result.push(encodeUnreserved(key) + '=' + tmp.join(','))
                    } else if (tmp.length !== 0) {
                        result.push(tmp.join(','))
                    }
                }
            }
        } else {
            if (operator === ';') {
                if (isDefined(value)) {
                    result.push(encodeUnreserved(key))
                }
            } else if (value === '' && (operator === '&' || operator === '?')) {
                result.push(encodeUnreserved(key) + '=')
            } else if (value === '') {
                result.push('')
            }
        }
        return result
    }
    var parseUrl = (template) => ({
        expand: expand.bind(null, template),
    })
    var expand = (template, context) => {
        var operators = ['+', '#', '.', '/', ';', '?', '&']
        template = template.replace(/\{([^\{\}]+)\}|([^\{\}]+)/g, (_, expression, literal) => {
            if (expression) {
                let operator = ''
                const values = []
                if (operators.indexOf(expression.charAt(0)) !== -1) {
                    operator = expression.charAt(0)
                    expression = expression.substr(1)
                }
                expression.split(/,/g).forEach((variable) => {
                    var tmp = /([^:\*]*)(?::(\d+)|(\*))?/.exec(variable)
                    values.push(getValues(context, operator, tmp[1], tmp[2] || tmp[3]))
                })
                if (operator && operator !== '+') {
                    var separator = ','
                    if (operator === '?') {
                        separator = '&'
                    } else if (operator !== '#') {
                        separator = operator
                    }
                    return (values.length !== 0 ? operator : '') + values.join(separator)
                } else {
                    return values.join(',')
                }
            } else {
                return encodeReserved(literal)
            }
        })
        if (template === '/') {
            return template
        } else {
            return template.replace(/\/$/, '')
        }
    }
    var parse = (options) => {
        const method = options.method.toUpperCase()
        let url = (options.url || '/').replace(/:([a-z]\w+)/g, '{$1}')
        const headers = Object.assign({}, options.headers)
        let body
        const parameters = omit(options, [
            'method',
            'baseUrl',
            'url',
            'headers',
            'request',
            'mediaType',
        ])
        const urlVariableNames = extractUrlVariableNames(url)
        url = parseUrl(url).expand(parameters)
        if (!/^http/.test(url)) {
            url = options.baseUrl + url
        }
        const omittedParameters = Object.keys(options)
            .filter((option) => urlVariableNames.includes(option))
            .concat('baseUrl')
        const remainingParameters = omit(parameters, omittedParameters)
        const isBinaryRequest = /application\/octet-stream/i.test(headers.accept)
        if (!isBinaryRequest) {
            if (options.mediaType.format) {
                headers.accept = headers.accept
                    .split(/,/)
                    .map((format) =>
                        format.replace(
                            /application\/vnd(\.\w+)(\.v3)?(\.\w+)?(\+json)?$/,
                            `application/vnd\$1\$2.${options.mediaType.format}`
                        )
                    )
                    .join(',')
            }
            if (url.endsWith('/graphql')) {
                if (options.mediaType.previews?.length) {
                    const previewsFromAcceptHeader =
                        headers.accept.match(/[\w-]+(?=-preview)/g) || []
                    headers.accept = previewsFromAcceptHeader
                        .concat(options.mediaType.previews)
                        .map((preview) => {
                            const format = options.mediaType.format
                                ? `.${options.mediaType.format}`
                                : '+json'
                            return `application/vnd.github.${preview}-preview${format}`
                        })
                        .join(',')
                }
            }
        }
        if (['GET', 'HEAD'].includes(method)) {
            url = addQueryParameters(url, remainingParameters)
        } else {
            if ('data' in remainingParameters) {
                body = remainingParameters.data
            } else {
                if (Object.keys(remainingParameters).length) {
                    body = remainingParameters
                }
            }
        }
        if (!headers['content-type'] && typeof body !== 'undefined') {
            headers['content-type'] = 'application/json; charset=utf-8'
        }
        if (['PATCH', 'PUT'].includes(method) && typeof body === 'undefined') {
            body = ''
        }
        return Object.assign(
            { method, url, headers },
            typeof body !== 'undefined' ? { body } : null,
            options.request ? { request: options.request } : null
        )
    }
    var endpointWithDefaults = (defaults, route, options) => parse(merge(defaults, route, options))
    var withDefaults = (oldDefaults, newDefaults) => {
        const DEFAULTS2 = merge(oldDefaults, newDefaults)
        const endpoint2 = endpointWithDefaults.bind(null, DEFAULTS2)
        return Object.assign(endpoint2, {
            DEFAULTS: DEFAULTS2,
            defaults: withDefaults.bind(null, DEFAULTS2),
            merge: merge.bind(null, DEFAULTS2),
            parse,
        })
    }
    var __defProp2 = Object.defineProperty
    var __getOwnPropDesc = Object.getOwnPropertyDescriptor
    var __getOwnPropNames2 = Object.getOwnPropertyNames
    var __hasOwnProp2 = Object.prototype.hasOwnProperty
    var __export = (target, all) => {
        for (var name in all) __defProp2(target, name, { get: all[name], enumerable: true })
    }
    var __copyProps = (to, from, except, desc) => {
        if ((from && typeof from === 'object') || typeof from === 'function') {
            for (const key of __getOwnPropNames2(from))
                if (!__hasOwnProp2.call(to, key) && key !== except)
                    __defProp2(to, key, {
                        get: () => from[key],
                        enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable,
                    })
        }
        return to
    }
    var __toCommonJS = (mod) => __copyProps(__defProp2({}, '__esModule', { value: true }), mod)
    var dist_src_exports = {}
    __export(dist_src_exports, {
        endpoint: () => endpoint,
    })
    module.exports = __toCommonJS(dist_src_exports)
    var import_universal_user_agent = require_dist_node()
    var VERSION = '9.0.5'
    var userAgent = `octokit-endpoint.js/${VERSION} ${(0, import_universal_user_agent.getUserAgent)()}`
    var DEFAULTS = {
        method: 'GET',
        baseUrl: 'https://api.github.com',
        headers: {
            accept: 'application/vnd.github.v3+json',
            'user-agent': userAgent,
        },
        mediaType: {
            format: '',
        },
    }
    var urlVariableRegex = /\{[^}]+\}/g
    var endpoint = withDefaults(null, DEFAULTS)
})

// node_modules/deprecation/dist-node/index.js
var require_dist_node3 = __commonJS((exports) => {
    Object.defineProperty(exports, '__esModule', { value: true })

    class Deprecation extends Error {
        constructor(message) {
            super(message)
            if (Error.captureStackTrace) {
                Error.captureStackTrace(this, this.constructor)
            }
            this.name = 'Deprecation'
        }
    }
    exports.Deprecation = Deprecation
})

// node_modules/wrappy/wrappy.js
var require_wrappy = __commonJS((exports, module) => {
    var wrappy = (fn, cb) => {
        if (fn && cb) return wrappy(fn)(cb)
        if (typeof fn !== 'function') throw new TypeError('need wrapper function')
        Object.keys(fn).forEach((k) => {
            wrapper[k] = fn[k]
        })
        return wrapper
        function wrapper() {
            var args = new Array(arguments.length)
            for (var i = 0; i < args.length; i++) {
                args[i] = arguments[i]
            }
            var ret = fn.apply(this, args)
            var cb2 = args[args.length - 1]
            if (typeof ret === 'function' && ret !== cb2) {
                Object.keys(cb2).forEach((k) => {
                    ret[k] = cb2[k]
                })
            }
            return ret
        }
    }
    module.exports = wrappy
})

// node_modules/once/once.js
var require_once = __commonJS((exports, module) => {
    var once = (fn) => {
        var f = function () {
            if (f.called) return f.value
            f.called = true
            return (f.value = fn.apply(this, arguments))
        }
        f.called = false
        return f
    }
    var onceStrict = (fn) => {
        var f = function () {
            if (f.called) throw new Error(f.onceError)
            f.called = true
            return (f.value = fn.apply(this, arguments))
        }
        var name = fn.name || 'Function wrapped with `once`'
        f.onceError = name + " shouldn't be called more than once"
        f.called = false
        return f
    }
    var wrappy = require_wrappy()
    module.exports = wrappy(once)
    module.exports.strict = wrappy(onceStrict)
    once.proto = once(() => {
        Object.defineProperty(Function.prototype, 'once', {
            value: function () {
                return once(this)
            },
            configurable: true,
        })
        Object.defineProperty(Function.prototype, 'onceStrict', {
            value: function () {
                return onceStrict(this)
            },
            configurable: true,
        })
    })
})

// node_modules/@octokit/request-error/dist-node/index.js
var require_dist_node4 = __commonJS((exports, module) => {
    var __create2 = Object.create
    var __defProp2 = Object.defineProperty
    var __getOwnPropDesc = Object.getOwnPropertyDescriptor
    var __getOwnPropNames2 = Object.getOwnPropertyNames
    var __getProtoOf2 = Object.getPrototypeOf
    var __hasOwnProp2 = Object.prototype.hasOwnProperty
    var __export = (target, all) => {
        for (var name in all) __defProp2(target, name, { get: all[name], enumerable: true })
    }
    var __copyProps = (to, from, except, desc) => {
        if ((from && typeof from === 'object') || typeof from === 'function') {
            for (const key of __getOwnPropNames2(from))
                if (!__hasOwnProp2.call(to, key) && key !== except)
                    __defProp2(to, key, {
                        get: () => from[key],
                        enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable,
                    })
        }
        return to
    }
    var __toESM2 = (mod, isNodeMode, target) => (
        (target = mod != null ? __create2(__getProtoOf2(mod)) : {}),
        __copyProps(
            isNodeMode || !mod || !mod.__esModule
                ? __defProp2(target, 'default', { value: mod, enumerable: true })
                : target,
            mod
        )
    )
    var __toCommonJS = (mod) => __copyProps(__defProp2({}, '__esModule', { value: true }), mod)
    var dist_src_exports = {}
    __export(dist_src_exports, {
        RequestError: () => RequestError,
    })
    module.exports = __toCommonJS(dist_src_exports)
    var import_deprecation = require_dist_node3()
    var import_once = __toESM2(require_once())
    var logOnceCode = (0, import_once.default)((deprecation) => console.warn(deprecation))
    var logOnceHeaders = (0, import_once.default)((deprecation) => console.warn(deprecation))
    var RequestError = class extends Error {
        constructor(message, statusCode, options) {
            super(message)
            if (Error.captureStackTrace) {
                Error.captureStackTrace(this, this.constructor)
            }
            this.name = 'HttpError'
            this.status = statusCode
            let headers
            if ('headers' in options && typeof options.headers !== 'undefined') {
                headers = options.headers
            }
            if ('response' in options) {
                this.response = options.response
                headers = options.response.headers
            }
            const requestCopy = Object.assign({}, options.request)
            if (options.request.headers.authorization) {
                requestCopy.headers = Object.assign({}, options.request.headers, {
                    authorization: options.request.headers.authorization.replace(
                        / .*$/,
                        ' [REDACTED]'
                    ),
                })
            }
            requestCopy.url = requestCopy.url
                .replace(/\bclient_secret=\w+/g, 'client_secret=[REDACTED]')
                .replace(/\baccess_token=\w+/g, 'access_token=[REDACTED]')
            this.request = requestCopy
            Object.defineProperty(this, 'code', {
                get() {
                    logOnceCode(
                        new import_deprecation.Deprecation(
                            '[@octokit/request-error] `error.code` is deprecated, use `error.status`.'
                        )
                    )
                    return statusCode
                },
            })
            Object.defineProperty(this, 'headers', {
                get() {
                    logOnceHeaders(
                        new import_deprecation.Deprecation(
                            '[@octokit/request-error] `error.headers` is deprecated, use `error.response.headers`.'
                        )
                    )
                    return headers || {}
                },
            })
        }
    }
})

// node_modules/@octokit/request/dist-node/index.js
var require_dist_node5 = __commonJS((exports, module) => {
    var isPlainObject = (value) => {
        if (typeof value !== 'object' || value === null) return false
        if (Object.prototype.toString.call(value) !== '[object Object]') return false
        const proto = Object.getPrototypeOf(value)
        if (proto === null) return true
        const Ctor = Object.prototype.hasOwnProperty.call(proto, 'constructor') && proto.constructor
        return (
            typeof Ctor === 'function' &&
            Ctor instanceof Ctor &&
            Function.prototype.call(Ctor) === Function.prototype.call(value)
        )
    }
    var getBufferResponse = (response) => response.arrayBuffer()
    var fetchWrapper = (requestOptions) => {
        var _a, _b, _c, _d
        const log =
            requestOptions.request && requestOptions.request.log
                ? requestOptions.request.log
                : console
        const parseSuccessResponseBody =
            ((_a = requestOptions.request) == null ? undefined : _a.parseSuccessResponseBody) !==
            false
        if (isPlainObject(requestOptions.body) || Array.isArray(requestOptions.body)) {
            requestOptions.body = JSON.stringify(requestOptions.body)
        }
        const headers = {}
        let status
        let url
        let { fetch } = globalThis
        if ((_b = requestOptions.request) == null ? undefined : _b.fetch) {
            fetch = requestOptions.request.fetch
        }
        if (!fetch) {
            throw new Error(
                'fetch is not set. Please pass a fetch implementation as new Octokit({ request: { fetch }}). Learn more at https://github.com/octokit/octokit.js/#fetch-missing'
            )
        }
        return fetch(requestOptions.url, {
            method: requestOptions.method,
            body: requestOptions.body,
            redirect: (_c = requestOptions.request) == null ? undefined : _c.redirect,
            headers: requestOptions.headers,
            signal: (_d = requestOptions.request) == null ? undefined : _d.signal,
            ...(requestOptions.body && { duplex: 'half' }),
        })
            .then(async (response) => {
                url = response.url
                status = response.status
                for (const keyAndValue of response.headers) {
                    headers[keyAndValue[0]] = keyAndValue[1]
                }
                if ('deprecation' in headers) {
                    const matches =
                        headers.link && headers.link.match(/<([^>]+)>; rel="deprecation"/)
                    const deprecationLink = matches && matches.pop()
                    log.warn(
                        `[@octokit/request] "${requestOptions.method} ${requestOptions.url}" is deprecated. It is scheduled to be removed on ${headers.sunset}${deprecationLink ? `. See ${deprecationLink}` : ''}`
                    )
                }
                if (status === 204 || status === 205) {
                    return
                }
                if (requestOptions.method === 'HEAD') {
                    if (status < 400) {
                        return
                    }
                    throw new import_request_error.RequestError(response.statusText, status, {
                        response: {
                            url,
                            status,
                            headers,
                            data: undefined,
                        },
                        request: requestOptions,
                    })
                }
                if (status === 304) {
                    throw new import_request_error.RequestError('Not modified', status, {
                        response: {
                            url,
                            status,
                            headers,
                            data: await getResponseData(response),
                        },
                        request: requestOptions,
                    })
                }
                if (status >= 400) {
                    const data = await getResponseData(response)
                    const error = new import_request_error.RequestError(
                        toErrorMessage(data),
                        status,
                        {
                            response: {
                                url,
                                status,
                                headers,
                                data,
                            },
                            request: requestOptions,
                        }
                    )
                    throw error
                }
                return parseSuccessResponseBody ? await getResponseData(response) : response.body
            })
            .then((data) => {
                return {
                    status,
                    url,
                    headers,
                    data,
                }
            })
            .catch((error) => {
                if (error instanceof import_request_error.RequestError) throw error
                else if (error.name === 'AbortError') throw error
                let message = error.message
                if (error.name === 'TypeError' && 'cause' in error) {
                    if (error.cause instanceof Error) {
                        message = error.cause.message
                    } else if (typeof error.cause === 'string') {
                        message = error.cause
                    }
                }
                throw new import_request_error.RequestError(message, 500, {
                    request: requestOptions,
                })
            })
    }
    async function getResponseData(response) {
        const contentType = response.headers.get('content-type')
        if (/application\/json/.test(contentType)) {
            return response
                .json()
                .catch(() => response.text())
                .catch(() => '')
        }
        if (!contentType || /^text\/|charset=utf-8$/.test(contentType)) {
            return response.text()
        }
        return getBufferResponse(response)
    }
    var toErrorMessage = (data) => {
        if (typeof data === 'string') return data
        let suffix
        if ('documentation_url' in data) {
            suffix = ` - ${data.documentation_url}`
        } else {
            suffix = ''
        }
        if ('message' in data) {
            if (Array.isArray(data.errors)) {
                return `${data.message}: ${data.errors.map(JSON.stringify).join(', ')}${suffix}`
            }
            return `${data.message}${suffix}`
        }
        return `Unknown error: ${JSON.stringify(data)}`
    }
    var withDefaults = (oldEndpoint, newDefaults) => {
        const endpoint2 = oldEndpoint.defaults(newDefaults)
        const newApi = (route, parameters) => {
            const endpointOptions = endpoint2.merge(route, parameters)
            if (!endpointOptions.request || !endpointOptions.request.hook) {
                return fetchWrapper(endpoint2.parse(endpointOptions))
            }
            const request2 = (route2, parameters2) => {
                return fetchWrapper(endpoint2.parse(endpoint2.merge(route2, parameters2)))
            }
            Object.assign(request2, {
                endpoint: endpoint2,
                defaults: withDefaults.bind(null, endpoint2),
            })
            return endpointOptions.request.hook(request2, endpointOptions)
        }
        return Object.assign(newApi, {
            endpoint: endpoint2,
            defaults: withDefaults.bind(null, endpoint2),
        })
    }
    var __defProp2 = Object.defineProperty
    var __getOwnPropDesc = Object.getOwnPropertyDescriptor
    var __getOwnPropNames2 = Object.getOwnPropertyNames
    var __hasOwnProp2 = Object.prototype.hasOwnProperty
    var __export = (target, all) => {
        for (var name in all) __defProp2(target, name, { get: all[name], enumerable: true })
    }
    var __copyProps = (to, from, except, desc) => {
        if ((from && typeof from === 'object') || typeof from === 'function') {
            for (const key of __getOwnPropNames2(from))
                if (!__hasOwnProp2.call(to, key) && key !== except)
                    __defProp2(to, key, {
                        get: () => from[key],
                        enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable,
                    })
        }
        return to
    }
    var __toCommonJS = (mod) => __copyProps(__defProp2({}, '__esModule', { value: true }), mod)
    var dist_src_exports = {}
    __export(dist_src_exports, {
        request: () => request,
    })
    module.exports = __toCommonJS(dist_src_exports)
    var import_endpoint = require_dist_node2()
    var import_universal_user_agent = require_dist_node()
    var VERSION = '8.4.0'
    var import_request_error = require_dist_node4()
    var request = withDefaults(import_endpoint.endpoint, {
        headers: {
            'user-agent': `octokit-request.js/${VERSION} ${(0, import_universal_user_agent.getUserAgent)()}`,
        },
    })
})

// node_modules/@octokit/graphql/dist-node/index.js
var require_dist_node6 = __commonJS((exports, module) => {
    var _buildMessageForResponseErrors = (data) =>
        `Request failed due to following response errors:
` + data.errors.map((e) => ` - ${e.message}`).join('\n')
    var graphql = (request2, query, options) => {
        if (options) {
            if (typeof query === 'string' && 'query' in options) {
                return Promise.reject(
                    new Error(`[@octokit/graphql] "query" cannot be used as variable name`)
                )
            }
            for (const key in options) {
                if (!FORBIDDEN_VARIABLE_OPTIONS.includes(key)) continue
                return Promise.reject(
                    new Error(`[@octokit/graphql] "${key}" cannot be used as variable name`)
                )
            }
        }
        const parsedOptions = typeof query === 'string' ? Object.assign({ query }, options) : query
        const requestOptions = Object.keys(parsedOptions).reduce((result, key) => {
            if (NON_VARIABLE_OPTIONS.includes(key)) {
                result[key] = parsedOptions[key]
                return result
            }
            if (!result.variables) {
                result.variables = {}
            }
            result.variables[key] = parsedOptions[key]
            return result
        }, {})
        const baseUrl = parsedOptions.baseUrl || request2.endpoint.DEFAULTS.baseUrl
        if (GHES_V3_SUFFIX_REGEX.test(baseUrl)) {
            requestOptions.url = baseUrl.replace(GHES_V3_SUFFIX_REGEX, '/api/graphql')
        }
        return request2(requestOptions).then((response) => {
            if (response.data.errors) {
                const headers = {}
                for (const key of Object.keys(response.headers)) {
                    headers[key] = response.headers[key]
                }
                throw new GraphqlResponseError(requestOptions, headers, response.data)
            }
            return response.data.data
        })
    }
    var withDefaults = (request2, newDefaults) => {
        const newRequest = request2.defaults(newDefaults)
        const newApi = (query, options) => {
            return graphql(newRequest, query, options)
        }
        return Object.assign(newApi, {
            defaults: withDefaults.bind(null, newRequest),
            endpoint: newRequest.endpoint,
        })
    }
    var withCustomRequest = (customRequest) =>
        withDefaults(customRequest, {
            method: 'POST',
            url: '/graphql',
        })
    var __defProp2 = Object.defineProperty
    var __getOwnPropDesc = Object.getOwnPropertyDescriptor
    var __getOwnPropNames2 = Object.getOwnPropertyNames
    var __hasOwnProp2 = Object.prototype.hasOwnProperty
    var __export = (target, all) => {
        for (var name in all) __defProp2(target, name, { get: all[name], enumerable: true })
    }
    var __copyProps = (to, from, except, desc) => {
        if ((from && typeof from === 'object') || typeof from === 'function') {
            for (const key of __getOwnPropNames2(from))
                if (!__hasOwnProp2.call(to, key) && key !== except)
                    __defProp2(to, key, {
                        get: () => from[key],
                        enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable,
                    })
        }
        return to
    }
    var __toCommonJS = (mod) => __copyProps(__defProp2({}, '__esModule', { value: true }), mod)
    var dist_src_exports = {}
    __export(dist_src_exports, {
        GraphqlResponseError: () => GraphqlResponseError,
        graphql: () => graphql2,
        withCustomRequest: () => withCustomRequest,
    })
    module.exports = __toCommonJS(dist_src_exports)
    var import_request3 = require_dist_node5()
    var import_universal_user_agent = require_dist_node()
    var VERSION = '7.1.0'
    var import_request2 = require_dist_node5()
    var import_request = require_dist_node5()
    var GraphqlResponseError = class extends Error {
        constructor(request2, headers, response) {
            super(_buildMessageForResponseErrors(response))
            this.request = request2
            this.headers = headers
            this.response = response
            this.name = 'GraphqlResponseError'
            this.errors = response.errors
            this.data = response.data
            if (Error.captureStackTrace) {
                Error.captureStackTrace(this, this.constructor)
            }
        }
    }
    var NON_VARIABLE_OPTIONS = [
        'method',
        'baseUrl',
        'url',
        'headers',
        'request',
        'query',
        'mediaType',
    ]
    var FORBIDDEN_VARIABLE_OPTIONS = ['query', 'method', 'url']
    var GHES_V3_SUFFIX_REGEX = /\/api\/v3\/?$/
    var graphql2 = withDefaults(import_request3.request, {
        headers: {
            'user-agent': `octokit-graphql.js/${VERSION} ${(0, import_universal_user_agent.getUserAgent)()}`,
        },
        method: 'POST',
        url: '/graphql',
    })
})

// node_modules/@octokit/auth-token/dist-node/index.js
var require_dist_node7 = __commonJS((exports, module) => {
    async function auth(token) {
        const isApp = token.split(/\./).length === 3
        const isInstallation =
            REGEX_IS_INSTALLATION_LEGACY.test(token) || REGEX_IS_INSTALLATION.test(token)
        const isUserToServer = REGEX_IS_USER_TO_SERVER.test(token)
        const tokenType = isApp
            ? 'app'
            : isInstallation
              ? 'installation'
              : isUserToServer
                ? 'user-to-server'
                : 'oauth'
        return {
            type: 'token',
            token,
            tokenType,
        }
    }
    var withAuthorizationPrefix = (token) => {
        if (token.split(/\./).length === 3) {
            return `bearer ${token}`
        }
        return `token ${token}`
    }
    async function hook(token, request, route, parameters) {
        const endpoint = request.endpoint.merge(route, parameters)
        endpoint.headers.authorization = withAuthorizationPrefix(token)
        return request(endpoint)
    }
    var __defProp2 = Object.defineProperty
    var __getOwnPropDesc = Object.getOwnPropertyDescriptor
    var __getOwnPropNames2 = Object.getOwnPropertyNames
    var __hasOwnProp2 = Object.prototype.hasOwnProperty
    var __export = (target, all) => {
        for (var name in all) __defProp2(target, name, { get: all[name], enumerable: true })
    }
    var __copyProps = (to, from, except, desc) => {
        if ((from && typeof from === 'object') || typeof from === 'function') {
            for (const key of __getOwnPropNames2(from))
                if (!__hasOwnProp2.call(to, key) && key !== except)
                    __defProp2(to, key, {
                        get: () => from[key],
                        enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable,
                    })
        }
        return to
    }
    var __toCommonJS = (mod) => __copyProps(__defProp2({}, '__esModule', { value: true }), mod)
    var dist_src_exports = {}
    __export(dist_src_exports, {
        createTokenAuth: () => createTokenAuth,
    })
    module.exports = __toCommonJS(dist_src_exports)
    var REGEX_IS_INSTALLATION_LEGACY = /^v1\./
    var REGEX_IS_INSTALLATION = /^ghs_/
    var REGEX_IS_USER_TO_SERVER = /^ghu_/
    var createTokenAuth = function createTokenAuth2(token) {
        if (!token) {
            throw new Error('[@octokit/auth-token] No token passed to createTokenAuth')
        }
        if (typeof token !== 'string') {
            throw new Error('[@octokit/auth-token] Token passed to createTokenAuth is not a string')
        }
        token = token.replace(/^(token|bearer) +/i, '')
        return Object.assign(auth.bind(null, token), {
            hook: hook.bind(null, token),
        })
    }
})

// node_modules/@octokit/core/dist-node/index.js
var require_dist_node8 = __commonJS((exports, module) => {
    var __defProp2 = Object.defineProperty
    var __getOwnPropDesc = Object.getOwnPropertyDescriptor
    var __getOwnPropNames2 = Object.getOwnPropertyNames
    var __hasOwnProp2 = Object.prototype.hasOwnProperty
    var __export = (target, all) => {
        for (var name in all) __defProp2(target, name, { get: all[name], enumerable: true })
    }
    var __copyProps = (to, from, except, desc) => {
        if ((from && typeof from === 'object') || typeof from === 'function') {
            for (const key of __getOwnPropNames2(from))
                if (!__hasOwnProp2.call(to, key) && key !== except)
                    __defProp2(to, key, {
                        get: () => from[key],
                        enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable,
                    })
        }
        return to
    }
    var __toCommonJS = (mod) => __copyProps(__defProp2({}, '__esModule', { value: true }), mod)
    var dist_src_exports = {}
    __export(dist_src_exports, {
        Octokit: () => Octokit,
    })
    module.exports = __toCommonJS(dist_src_exports)
    var import_universal_user_agent = require_dist_node()
    var import_before_after_hook = require_before_after_hook()
    var import_request = require_dist_node5()
    var import_graphql = require_dist_node6()
    var import_auth_token = require_dist_node7()
    var VERSION = '5.2.0'
    var noop = () => {}
    var consoleWarn = console.warn.bind(console)
    var consoleError = console.error.bind(console)
    var userAgentTrail = `octokit-core.js/${VERSION} ${(0, import_universal_user_agent.getUserAgent)()}`
    var Octokit = class {
        static {
            this.VERSION = VERSION
        }
        static defaults(defaults) {
            const OctokitWithDefaults = class extends this {
                constructor(...args) {
                    const options = args[0] || {}
                    if (typeof defaults === 'function') {
                        super(defaults(options))
                        return
                    }
                    super(
                        Object.assign(
                            {},
                            defaults,
                            options,
                            options.userAgent && defaults.userAgent
                                ? {
                                      userAgent: `${options.userAgent} ${defaults.userAgent}`,
                                  }
                                : null
                        )
                    )
                }
            }
            return OctokitWithDefaults
        }
        static {
            this.plugins = []
        }
        static plugin(...newPlugins) {
            const currentPlugins = this.plugins
            const NewOctokit = class extends this {
                static {
                    this.plugins = currentPlugins.concat(
                        newPlugins.filter((plugin) => !currentPlugins.includes(plugin))
                    )
                }
            }
            return NewOctokit
        }
        constructor(options = {}) {
            const hook = new import_before_after_hook.Collection()
            const requestDefaults = {
                baseUrl: import_request.request.endpoint.DEFAULTS.baseUrl,
                headers: {},
                request: Object.assign({}, options.request, {
                    hook: hook.bind(null, 'request'),
                }),
                mediaType: {
                    previews: [],
                    format: '',
                },
            }
            requestDefaults.headers['user-agent'] = options.userAgent
                ? `${options.userAgent} ${userAgentTrail}`
                : userAgentTrail
            if (options.baseUrl) {
                requestDefaults.baseUrl = options.baseUrl
            }
            if (options.previews) {
                requestDefaults.mediaType.previews = options.previews
            }
            if (options.timeZone) {
                requestDefaults.headers['time-zone'] = options.timeZone
            }
            this.request = import_request.request.defaults(requestDefaults)
            this.graphql = (0, import_graphql.withCustomRequest)(this.request).defaults(
                requestDefaults
            )
            this.log = Object.assign(
                {
                    debug: noop,
                    info: noop,
                    warn: consoleWarn,
                    error: consoleError,
                },
                options.log
            )
            this.hook = hook
            if (!options.authStrategy) {
                if (!options.auth) {
                    this.auth = async () => ({
                        type: 'unauthenticated',
                    })
                } else {
                    const auth = (0, import_auth_token.createTokenAuth)(options.auth)
                    hook.wrap('request', auth.hook)
                    this.auth = auth
                }
            } else {
                const { authStrategy, ...otherOptions } = options
                const auth = authStrategy(
                    Object.assign(
                        {
                            request: this.request,
                            log: this.log,
                            octokit: this,
                            octokitOptions: otherOptions,
                        },
                        options.auth
                    )
                )
                hook.wrap('request', auth.hook)
                this.auth = auth
            }
            const classConstructor = this.constructor
            for (let i = 0; i < classConstructor.plugins.length; ++i) {
                Object.assign(this, classConstructor.plugins[i](this, options))
            }
        }
    }
})

// node_modules/@octokit/plugin-rest-endpoint-methods/dist-node/index.js
var require_dist_node9 = __commonJS((exports, module) => {
    var endpointsToMethods = (octokit) => {
        const newMethods = {}
        for (const scope of endpointMethodsMap.keys()) {
            newMethods[scope] = new Proxy({ octokit, scope, cache: {} }, handler)
        }
        return newMethods
    }
    var decorate = (octokit, scope, methodName, defaults, decorations) => {
        const requestWithDefaults = octokit.request.defaults(defaults)
        function withDecorations(...args) {
            let options = requestWithDefaults.endpoint.merge(...args)
            if (decorations.mapToData) {
                options = Object.assign({}, options, {
                    data: options[decorations.mapToData],
                    [decorations.mapToData]: undefined,
                })
                return requestWithDefaults(options)
            }
            if (decorations.renamed) {
                const [newScope, newMethodName] = decorations.renamed
                octokit.log.warn(
                    `octokit.${scope}.${methodName}() has been renamed to octokit.${newScope}.${newMethodName}()`
                )
            }
            if (decorations.deprecated) {
                octokit.log.warn(decorations.deprecated)
            }
            if (decorations.renamedParameters) {
                const options2 = requestWithDefaults.endpoint.merge(...args)
                for (const [name, alias] of Object.entries(decorations.renamedParameters)) {
                    if (name in options2) {
                        octokit.log.warn(
                            `"${name}" parameter is deprecated for "octokit.${scope}.${methodName}()". Use "${alias}" instead`
                        )
                        if (!(alias in options2)) {
                            options2[alias] = options2[name]
                        }
                        delete options2[name]
                    }
                }
                return requestWithDefaults(options2)
            }
            return requestWithDefaults(...args)
        }
        return Object.assign(withDecorations, requestWithDefaults)
    }
    var restEndpointMethods = (octokit) => {
        const api = endpointsToMethods(octokit)
        return {
            rest: api,
        }
    }
    var legacyRestEndpointMethods = (octokit) => {
        const api = endpointsToMethods(octokit)
        return {
            ...api,
            rest: api,
        }
    }
    var __defProp2 = Object.defineProperty
    var __getOwnPropDesc = Object.getOwnPropertyDescriptor
    var __getOwnPropNames2 = Object.getOwnPropertyNames
    var __hasOwnProp2 = Object.prototype.hasOwnProperty
    var __export = (target, all) => {
        for (var name in all) __defProp2(target, name, { get: all[name], enumerable: true })
    }
    var __copyProps = (to, from, except, desc) => {
        if ((from && typeof from === 'object') || typeof from === 'function') {
            for (const key of __getOwnPropNames2(from))
                if (!__hasOwnProp2.call(to, key) && key !== except)
                    __defProp2(to, key, {
                        get: () => from[key],
                        enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable,
                    })
        }
        return to
    }
    var __toCommonJS = (mod) => __copyProps(__defProp2({}, '__esModule', { value: true }), mod)
    var dist_src_exports = {}
    __export(dist_src_exports, {
        legacyRestEndpointMethods: () => legacyRestEndpointMethods,
        restEndpointMethods: () => restEndpointMethods,
    })
    module.exports = __toCommonJS(dist_src_exports)
    var VERSION = '10.4.1'
    var Endpoints = {
        actions: {
            addCustomLabelsToSelfHostedRunnerForOrg: [
                'POST /orgs/{org}/actions/runners/{runner_id}/labels',
            ],
            addCustomLabelsToSelfHostedRunnerForRepo: [
                'POST /repos/{owner}/{repo}/actions/runners/{runner_id}/labels',
            ],
            addSelectedRepoToOrgSecret: [
                'PUT /orgs/{org}/actions/secrets/{secret_name}/repositories/{repository_id}',
            ],
            addSelectedRepoToOrgVariable: [
                'PUT /orgs/{org}/actions/variables/{name}/repositories/{repository_id}',
            ],
            approveWorkflowRun: ['POST /repos/{owner}/{repo}/actions/runs/{run_id}/approve'],
            cancelWorkflowRun: ['POST /repos/{owner}/{repo}/actions/runs/{run_id}/cancel'],
            createEnvironmentVariable: [
                'POST /repositories/{repository_id}/environments/{environment_name}/variables',
            ],
            createOrUpdateEnvironmentSecret: [
                'PUT /repositories/{repository_id}/environments/{environment_name}/secrets/{secret_name}',
            ],
            createOrUpdateOrgSecret: ['PUT /orgs/{org}/actions/secrets/{secret_name}'],
            createOrUpdateRepoSecret: ['PUT /repos/{owner}/{repo}/actions/secrets/{secret_name}'],
            createOrgVariable: ['POST /orgs/{org}/actions/variables'],
            createRegistrationTokenForOrg: ['POST /orgs/{org}/actions/runners/registration-token'],
            createRegistrationTokenForRepo: [
                'POST /repos/{owner}/{repo}/actions/runners/registration-token',
            ],
            createRemoveTokenForOrg: ['POST /orgs/{org}/actions/runners/remove-token'],
            createRemoveTokenForRepo: ['POST /repos/{owner}/{repo}/actions/runners/remove-token'],
            createRepoVariable: ['POST /repos/{owner}/{repo}/actions/variables'],
            createWorkflowDispatch: [
                'POST /repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches',
            ],
            deleteActionsCacheById: ['DELETE /repos/{owner}/{repo}/actions/caches/{cache_id}'],
            deleteActionsCacheByKey: ['DELETE /repos/{owner}/{repo}/actions/caches{?key,ref}'],
            deleteArtifact: ['DELETE /repos/{owner}/{repo}/actions/artifacts/{artifact_id}'],
            deleteEnvironmentSecret: [
                'DELETE /repositories/{repository_id}/environments/{environment_name}/secrets/{secret_name}',
            ],
            deleteEnvironmentVariable: [
                'DELETE /repositories/{repository_id}/environments/{environment_name}/variables/{name}',
            ],
            deleteOrgSecret: ['DELETE /orgs/{org}/actions/secrets/{secret_name}'],
            deleteOrgVariable: ['DELETE /orgs/{org}/actions/variables/{name}'],
            deleteRepoSecret: ['DELETE /repos/{owner}/{repo}/actions/secrets/{secret_name}'],
            deleteRepoVariable: ['DELETE /repos/{owner}/{repo}/actions/variables/{name}'],
            deleteSelfHostedRunnerFromOrg: ['DELETE /orgs/{org}/actions/runners/{runner_id}'],
            deleteSelfHostedRunnerFromRepo: [
                'DELETE /repos/{owner}/{repo}/actions/runners/{runner_id}',
            ],
            deleteWorkflowRun: ['DELETE /repos/{owner}/{repo}/actions/runs/{run_id}'],
            deleteWorkflowRunLogs: ['DELETE /repos/{owner}/{repo}/actions/runs/{run_id}/logs'],
            disableSelectedRepositoryGithubActionsOrganization: [
                'DELETE /orgs/{org}/actions/permissions/repositories/{repository_id}',
            ],
            disableWorkflow: ['PUT /repos/{owner}/{repo}/actions/workflows/{workflow_id}/disable'],
            downloadArtifact: [
                'GET /repos/{owner}/{repo}/actions/artifacts/{artifact_id}/{archive_format}',
            ],
            downloadJobLogsForWorkflowRun: ['GET /repos/{owner}/{repo}/actions/jobs/{job_id}/logs'],
            downloadWorkflowRunAttemptLogs: [
                'GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}/logs',
            ],
            downloadWorkflowRunLogs: ['GET /repos/{owner}/{repo}/actions/runs/{run_id}/logs'],
            enableSelectedRepositoryGithubActionsOrganization: [
                'PUT /orgs/{org}/actions/permissions/repositories/{repository_id}',
            ],
            enableWorkflow: ['PUT /repos/{owner}/{repo}/actions/workflows/{workflow_id}/enable'],
            forceCancelWorkflowRun: [
                'POST /repos/{owner}/{repo}/actions/runs/{run_id}/force-cancel',
            ],
            generateRunnerJitconfigForOrg: ['POST /orgs/{org}/actions/runners/generate-jitconfig'],
            generateRunnerJitconfigForRepo: [
                'POST /repos/{owner}/{repo}/actions/runners/generate-jitconfig',
            ],
            getActionsCacheList: ['GET /repos/{owner}/{repo}/actions/caches'],
            getActionsCacheUsage: ['GET /repos/{owner}/{repo}/actions/cache/usage'],
            getActionsCacheUsageByRepoForOrg: ['GET /orgs/{org}/actions/cache/usage-by-repository'],
            getActionsCacheUsageForOrg: ['GET /orgs/{org}/actions/cache/usage'],
            getAllowedActionsOrganization: ['GET /orgs/{org}/actions/permissions/selected-actions'],
            getAllowedActionsRepository: [
                'GET /repos/{owner}/{repo}/actions/permissions/selected-actions',
            ],
            getArtifact: ['GET /repos/{owner}/{repo}/actions/artifacts/{artifact_id}'],
            getCustomOidcSubClaimForRepo: [
                'GET /repos/{owner}/{repo}/actions/oidc/customization/sub',
            ],
            getEnvironmentPublicKey: [
                'GET /repositories/{repository_id}/environments/{environment_name}/secrets/public-key',
            ],
            getEnvironmentSecret: [
                'GET /repositories/{repository_id}/environments/{environment_name}/secrets/{secret_name}',
            ],
            getEnvironmentVariable: [
                'GET /repositories/{repository_id}/environments/{environment_name}/variables/{name}',
            ],
            getGithubActionsDefaultWorkflowPermissionsOrganization: [
                'GET /orgs/{org}/actions/permissions/workflow',
            ],
            getGithubActionsDefaultWorkflowPermissionsRepository: [
                'GET /repos/{owner}/{repo}/actions/permissions/workflow',
            ],
            getGithubActionsPermissionsOrganization: ['GET /orgs/{org}/actions/permissions'],
            getGithubActionsPermissionsRepository: [
                'GET /repos/{owner}/{repo}/actions/permissions',
            ],
            getJobForWorkflowRun: ['GET /repos/{owner}/{repo}/actions/jobs/{job_id}'],
            getOrgPublicKey: ['GET /orgs/{org}/actions/secrets/public-key'],
            getOrgSecret: ['GET /orgs/{org}/actions/secrets/{secret_name}'],
            getOrgVariable: ['GET /orgs/{org}/actions/variables/{name}'],
            getPendingDeploymentsForRun: [
                'GET /repos/{owner}/{repo}/actions/runs/{run_id}/pending_deployments',
            ],
            getRepoPermissions: [
                'GET /repos/{owner}/{repo}/actions/permissions',
                {},
                { renamed: ['actions', 'getGithubActionsPermissionsRepository'] },
            ],
            getRepoPublicKey: ['GET /repos/{owner}/{repo}/actions/secrets/public-key'],
            getRepoSecret: ['GET /repos/{owner}/{repo}/actions/secrets/{secret_name}'],
            getRepoVariable: ['GET /repos/{owner}/{repo}/actions/variables/{name}'],
            getReviewsForRun: ['GET /repos/{owner}/{repo}/actions/runs/{run_id}/approvals'],
            getSelfHostedRunnerForOrg: ['GET /orgs/{org}/actions/runners/{runner_id}'],
            getSelfHostedRunnerForRepo: ['GET /repos/{owner}/{repo}/actions/runners/{runner_id}'],
            getWorkflow: ['GET /repos/{owner}/{repo}/actions/workflows/{workflow_id}'],
            getWorkflowAccessToRepository: ['GET /repos/{owner}/{repo}/actions/permissions/access'],
            getWorkflowRun: ['GET /repos/{owner}/{repo}/actions/runs/{run_id}'],
            getWorkflowRunAttempt: [
                'GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}',
            ],
            getWorkflowRunUsage: ['GET /repos/{owner}/{repo}/actions/runs/{run_id}/timing'],
            getWorkflowUsage: ['GET /repos/{owner}/{repo}/actions/workflows/{workflow_id}/timing'],
            listArtifactsForRepo: ['GET /repos/{owner}/{repo}/actions/artifacts'],
            listEnvironmentSecrets: [
                'GET /repositories/{repository_id}/environments/{environment_name}/secrets',
            ],
            listEnvironmentVariables: [
                'GET /repositories/{repository_id}/environments/{environment_name}/variables',
            ],
            listJobsForWorkflowRun: ['GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs'],
            listJobsForWorkflowRunAttempt: [
                'GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}/jobs',
            ],
            listLabelsForSelfHostedRunnerForOrg: [
                'GET /orgs/{org}/actions/runners/{runner_id}/labels',
            ],
            listLabelsForSelfHostedRunnerForRepo: [
                'GET /repos/{owner}/{repo}/actions/runners/{runner_id}/labels',
            ],
            listOrgSecrets: ['GET /orgs/{org}/actions/secrets'],
            listOrgVariables: ['GET /orgs/{org}/actions/variables'],
            listRepoOrganizationSecrets: ['GET /repos/{owner}/{repo}/actions/organization-secrets'],
            listRepoOrganizationVariables: [
                'GET /repos/{owner}/{repo}/actions/organization-variables',
            ],
            listRepoSecrets: ['GET /repos/{owner}/{repo}/actions/secrets'],
            listRepoVariables: ['GET /repos/{owner}/{repo}/actions/variables'],
            listRepoWorkflows: ['GET /repos/{owner}/{repo}/actions/workflows'],
            listRunnerApplicationsForOrg: ['GET /orgs/{org}/actions/runners/downloads'],
            listRunnerApplicationsForRepo: ['GET /repos/{owner}/{repo}/actions/runners/downloads'],
            listSelectedReposForOrgSecret: [
                'GET /orgs/{org}/actions/secrets/{secret_name}/repositories',
            ],
            listSelectedReposForOrgVariable: [
                'GET /orgs/{org}/actions/variables/{name}/repositories',
            ],
            listSelectedRepositoriesEnabledGithubActionsOrganization: [
                'GET /orgs/{org}/actions/permissions/repositories',
            ],
            listSelfHostedRunnersForOrg: ['GET /orgs/{org}/actions/runners'],
            listSelfHostedRunnersForRepo: ['GET /repos/{owner}/{repo}/actions/runners'],
            listWorkflowRunArtifacts: ['GET /repos/{owner}/{repo}/actions/runs/{run_id}/artifacts'],
            listWorkflowRuns: ['GET /repos/{owner}/{repo}/actions/workflows/{workflow_id}/runs'],
            listWorkflowRunsForRepo: ['GET /repos/{owner}/{repo}/actions/runs'],
            reRunJobForWorkflowRun: ['POST /repos/{owner}/{repo}/actions/jobs/{job_id}/rerun'],
            reRunWorkflow: ['POST /repos/{owner}/{repo}/actions/runs/{run_id}/rerun'],
            reRunWorkflowFailedJobs: [
                'POST /repos/{owner}/{repo}/actions/runs/{run_id}/rerun-failed-jobs',
            ],
            removeAllCustomLabelsFromSelfHostedRunnerForOrg: [
                'DELETE /orgs/{org}/actions/runners/{runner_id}/labels',
            ],
            removeAllCustomLabelsFromSelfHostedRunnerForRepo: [
                'DELETE /repos/{owner}/{repo}/actions/runners/{runner_id}/labels',
            ],
            removeCustomLabelFromSelfHostedRunnerForOrg: [
                'DELETE /orgs/{org}/actions/runners/{runner_id}/labels/{name}',
            ],
            removeCustomLabelFromSelfHostedRunnerForRepo: [
                'DELETE /repos/{owner}/{repo}/actions/runners/{runner_id}/labels/{name}',
            ],
            removeSelectedRepoFromOrgSecret: [
                'DELETE /orgs/{org}/actions/secrets/{secret_name}/repositories/{repository_id}',
            ],
            removeSelectedRepoFromOrgVariable: [
                'DELETE /orgs/{org}/actions/variables/{name}/repositories/{repository_id}',
            ],
            reviewCustomGatesForRun: [
                'POST /repos/{owner}/{repo}/actions/runs/{run_id}/deployment_protection_rule',
            ],
            reviewPendingDeploymentsForRun: [
                'POST /repos/{owner}/{repo}/actions/runs/{run_id}/pending_deployments',
            ],
            setAllowedActionsOrganization: ['PUT /orgs/{org}/actions/permissions/selected-actions'],
            setAllowedActionsRepository: [
                'PUT /repos/{owner}/{repo}/actions/permissions/selected-actions',
            ],
            setCustomLabelsForSelfHostedRunnerForOrg: [
                'PUT /orgs/{org}/actions/runners/{runner_id}/labels',
            ],
            setCustomLabelsForSelfHostedRunnerForRepo: [
                'PUT /repos/{owner}/{repo}/actions/runners/{runner_id}/labels',
            ],
            setCustomOidcSubClaimForRepo: [
                'PUT /repos/{owner}/{repo}/actions/oidc/customization/sub',
            ],
            setGithubActionsDefaultWorkflowPermissionsOrganization: [
                'PUT /orgs/{org}/actions/permissions/workflow',
            ],
            setGithubActionsDefaultWorkflowPermissionsRepository: [
                'PUT /repos/{owner}/{repo}/actions/permissions/workflow',
            ],
            setGithubActionsPermissionsOrganization: ['PUT /orgs/{org}/actions/permissions'],
            setGithubActionsPermissionsRepository: [
                'PUT /repos/{owner}/{repo}/actions/permissions',
            ],
            setSelectedReposForOrgSecret: [
                'PUT /orgs/{org}/actions/secrets/{secret_name}/repositories',
            ],
            setSelectedReposForOrgVariable: [
                'PUT /orgs/{org}/actions/variables/{name}/repositories',
            ],
            setSelectedRepositoriesEnabledGithubActionsOrganization: [
                'PUT /orgs/{org}/actions/permissions/repositories',
            ],
            setWorkflowAccessToRepository: ['PUT /repos/{owner}/{repo}/actions/permissions/access'],
            updateEnvironmentVariable: [
                'PATCH /repositories/{repository_id}/environments/{environment_name}/variables/{name}',
            ],
            updateOrgVariable: ['PATCH /orgs/{org}/actions/variables/{name}'],
            updateRepoVariable: ['PATCH /repos/{owner}/{repo}/actions/variables/{name}'],
        },
        activity: {
            checkRepoIsStarredByAuthenticatedUser: ['GET /user/starred/{owner}/{repo}'],
            deleteRepoSubscription: ['DELETE /repos/{owner}/{repo}/subscription'],
            deleteThreadSubscription: ['DELETE /notifications/threads/{thread_id}/subscription'],
            getFeeds: ['GET /feeds'],
            getRepoSubscription: ['GET /repos/{owner}/{repo}/subscription'],
            getThread: ['GET /notifications/threads/{thread_id}'],
            getThreadSubscriptionForAuthenticatedUser: [
                'GET /notifications/threads/{thread_id}/subscription',
            ],
            listEventsForAuthenticatedUser: ['GET /users/{username}/events'],
            listNotificationsForAuthenticatedUser: ['GET /notifications'],
            listOrgEventsForAuthenticatedUser: ['GET /users/{username}/events/orgs/{org}'],
            listPublicEvents: ['GET /events'],
            listPublicEventsForRepoNetwork: ['GET /networks/{owner}/{repo}/events'],
            listPublicEventsForUser: ['GET /users/{username}/events/public'],
            listPublicOrgEvents: ['GET /orgs/{org}/events'],
            listReceivedEventsForUser: ['GET /users/{username}/received_events'],
            listReceivedPublicEventsForUser: ['GET /users/{username}/received_events/public'],
            listRepoEvents: ['GET /repos/{owner}/{repo}/events'],
            listRepoNotificationsForAuthenticatedUser: ['GET /repos/{owner}/{repo}/notifications'],
            listReposStarredByAuthenticatedUser: ['GET /user/starred'],
            listReposStarredByUser: ['GET /users/{username}/starred'],
            listReposWatchedByUser: ['GET /users/{username}/subscriptions'],
            listStargazersForRepo: ['GET /repos/{owner}/{repo}/stargazers'],
            listWatchedReposForAuthenticatedUser: ['GET /user/subscriptions'],
            listWatchersForRepo: ['GET /repos/{owner}/{repo}/subscribers'],
            markNotificationsAsRead: ['PUT /notifications'],
            markRepoNotificationsAsRead: ['PUT /repos/{owner}/{repo}/notifications'],
            markThreadAsDone: ['DELETE /notifications/threads/{thread_id}'],
            markThreadAsRead: ['PATCH /notifications/threads/{thread_id}'],
            setRepoSubscription: ['PUT /repos/{owner}/{repo}/subscription'],
            setThreadSubscription: ['PUT /notifications/threads/{thread_id}/subscription'],
            starRepoForAuthenticatedUser: ['PUT /user/starred/{owner}/{repo}'],
            unstarRepoForAuthenticatedUser: ['DELETE /user/starred/{owner}/{repo}'],
        },
        apps: {
            addRepoToInstallation: [
                'PUT /user/installations/{installation_id}/repositories/{repository_id}',
                {},
                { renamed: ['apps', 'addRepoToInstallationForAuthenticatedUser'] },
            ],
            addRepoToInstallationForAuthenticatedUser: [
                'PUT /user/installations/{installation_id}/repositories/{repository_id}',
            ],
            checkToken: ['POST /applications/{client_id}/token'],
            createFromManifest: ['POST /app-manifests/{code}/conversions'],
            createInstallationAccessToken: [
                'POST /app/installations/{installation_id}/access_tokens',
            ],
            deleteAuthorization: ['DELETE /applications/{client_id}/grant'],
            deleteInstallation: ['DELETE /app/installations/{installation_id}'],
            deleteToken: ['DELETE /applications/{client_id}/token'],
            getAuthenticated: ['GET /app'],
            getBySlug: ['GET /apps/{app_slug}'],
            getInstallation: ['GET /app/installations/{installation_id}'],
            getOrgInstallation: ['GET /orgs/{org}/installation'],
            getRepoInstallation: ['GET /repos/{owner}/{repo}/installation'],
            getSubscriptionPlanForAccount: ['GET /marketplace_listing/accounts/{account_id}'],
            getSubscriptionPlanForAccountStubbed: [
                'GET /marketplace_listing/stubbed/accounts/{account_id}',
            ],
            getUserInstallation: ['GET /users/{username}/installation'],
            getWebhookConfigForApp: ['GET /app/hook/config'],
            getWebhookDelivery: ['GET /app/hook/deliveries/{delivery_id}'],
            listAccountsForPlan: ['GET /marketplace_listing/plans/{plan_id}/accounts'],
            listAccountsForPlanStubbed: [
                'GET /marketplace_listing/stubbed/plans/{plan_id}/accounts',
            ],
            listInstallationReposForAuthenticatedUser: [
                'GET /user/installations/{installation_id}/repositories',
            ],
            listInstallationRequestsForAuthenticatedApp: ['GET /app/installation-requests'],
            listInstallations: ['GET /app/installations'],
            listInstallationsForAuthenticatedUser: ['GET /user/installations'],
            listPlans: ['GET /marketplace_listing/plans'],
            listPlansStubbed: ['GET /marketplace_listing/stubbed/plans'],
            listReposAccessibleToInstallation: ['GET /installation/repositories'],
            listSubscriptionsForAuthenticatedUser: ['GET /user/marketplace_purchases'],
            listSubscriptionsForAuthenticatedUserStubbed: [
                'GET /user/marketplace_purchases/stubbed',
            ],
            listWebhookDeliveries: ['GET /app/hook/deliveries'],
            redeliverWebhookDelivery: ['POST /app/hook/deliveries/{delivery_id}/attempts'],
            removeRepoFromInstallation: [
                'DELETE /user/installations/{installation_id}/repositories/{repository_id}',
                {},
                { renamed: ['apps', 'removeRepoFromInstallationForAuthenticatedUser'] },
            ],
            removeRepoFromInstallationForAuthenticatedUser: [
                'DELETE /user/installations/{installation_id}/repositories/{repository_id}',
            ],
            resetToken: ['PATCH /applications/{client_id}/token'],
            revokeInstallationAccessToken: ['DELETE /installation/token'],
            scopeToken: ['POST /applications/{client_id}/token/scoped'],
            suspendInstallation: ['PUT /app/installations/{installation_id}/suspended'],
            unsuspendInstallation: ['DELETE /app/installations/{installation_id}/suspended'],
            updateWebhookConfigForApp: ['PATCH /app/hook/config'],
        },
        billing: {
            getGithubActionsBillingOrg: ['GET /orgs/{org}/settings/billing/actions'],
            getGithubActionsBillingUser: ['GET /users/{username}/settings/billing/actions'],
            getGithubPackagesBillingOrg: ['GET /orgs/{org}/settings/billing/packages'],
            getGithubPackagesBillingUser: ['GET /users/{username}/settings/billing/packages'],
            getSharedStorageBillingOrg: ['GET /orgs/{org}/settings/billing/shared-storage'],
            getSharedStorageBillingUser: ['GET /users/{username}/settings/billing/shared-storage'],
        },
        checks: {
            create: ['POST /repos/{owner}/{repo}/check-runs'],
            createSuite: ['POST /repos/{owner}/{repo}/check-suites'],
            get: ['GET /repos/{owner}/{repo}/check-runs/{check_run_id}'],
            getSuite: ['GET /repos/{owner}/{repo}/check-suites/{check_suite_id}'],
            listAnnotations: ['GET /repos/{owner}/{repo}/check-runs/{check_run_id}/annotations'],
            listForRef: ['GET /repos/{owner}/{repo}/commits/{ref}/check-runs'],
            listForSuite: ['GET /repos/{owner}/{repo}/check-suites/{check_suite_id}/check-runs'],
            listSuitesForRef: ['GET /repos/{owner}/{repo}/commits/{ref}/check-suites'],
            rerequestRun: ['POST /repos/{owner}/{repo}/check-runs/{check_run_id}/rerequest'],
            rerequestSuite: ['POST /repos/{owner}/{repo}/check-suites/{check_suite_id}/rerequest'],
            setSuitesPreferences: ['PATCH /repos/{owner}/{repo}/check-suites/preferences'],
            update: ['PATCH /repos/{owner}/{repo}/check-runs/{check_run_id}'],
        },
        codeScanning: {
            deleteAnalysis: [
                'DELETE /repos/{owner}/{repo}/code-scanning/analyses/{analysis_id}{?confirm_delete}',
            ],
            getAlert: [
                'GET /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}',
                {},
                { renamedParameters: { alert_id: 'alert_number' } },
            ],
            getAnalysis: ['GET /repos/{owner}/{repo}/code-scanning/analyses/{analysis_id}'],
            getCodeqlDatabase: [
                'GET /repos/{owner}/{repo}/code-scanning/codeql/databases/{language}',
            ],
            getDefaultSetup: ['GET /repos/{owner}/{repo}/code-scanning/default-setup'],
            getSarif: ['GET /repos/{owner}/{repo}/code-scanning/sarifs/{sarif_id}'],
            listAlertInstances: [
                'GET /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}/instances',
            ],
            listAlertsForOrg: ['GET /orgs/{org}/code-scanning/alerts'],
            listAlertsForRepo: ['GET /repos/{owner}/{repo}/code-scanning/alerts'],
            listAlertsInstances: [
                'GET /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}/instances',
                {},
                { renamed: ['codeScanning', 'listAlertInstances'] },
            ],
            listCodeqlDatabases: ['GET /repos/{owner}/{repo}/code-scanning/codeql/databases'],
            listRecentAnalyses: ['GET /repos/{owner}/{repo}/code-scanning/analyses'],
            updateAlert: ['PATCH /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}'],
            updateDefaultSetup: ['PATCH /repos/{owner}/{repo}/code-scanning/default-setup'],
            uploadSarif: ['POST /repos/{owner}/{repo}/code-scanning/sarifs'],
        },
        codesOfConduct: {
            getAllCodesOfConduct: ['GET /codes_of_conduct'],
            getConductCode: ['GET /codes_of_conduct/{key}'],
        },
        codespaces: {
            addRepositoryForSecretForAuthenticatedUser: [
                'PUT /user/codespaces/secrets/{secret_name}/repositories/{repository_id}',
            ],
            addSelectedRepoToOrgSecret: [
                'PUT /orgs/{org}/codespaces/secrets/{secret_name}/repositories/{repository_id}',
            ],
            checkPermissionsForDevcontainer: [
                'GET /repos/{owner}/{repo}/codespaces/permissions_check',
            ],
            codespaceMachinesForAuthenticatedUser: [
                'GET /user/codespaces/{codespace_name}/machines',
            ],
            createForAuthenticatedUser: ['POST /user/codespaces'],
            createOrUpdateOrgSecret: ['PUT /orgs/{org}/codespaces/secrets/{secret_name}'],
            createOrUpdateRepoSecret: [
                'PUT /repos/{owner}/{repo}/codespaces/secrets/{secret_name}',
            ],
            createOrUpdateSecretForAuthenticatedUser: [
                'PUT /user/codespaces/secrets/{secret_name}',
            ],
            createWithPrForAuthenticatedUser: [
                'POST /repos/{owner}/{repo}/pulls/{pull_number}/codespaces',
            ],
            createWithRepoForAuthenticatedUser: ['POST /repos/{owner}/{repo}/codespaces'],
            deleteForAuthenticatedUser: ['DELETE /user/codespaces/{codespace_name}'],
            deleteFromOrganization: [
                'DELETE /orgs/{org}/members/{username}/codespaces/{codespace_name}',
            ],
            deleteOrgSecret: ['DELETE /orgs/{org}/codespaces/secrets/{secret_name}'],
            deleteRepoSecret: ['DELETE /repos/{owner}/{repo}/codespaces/secrets/{secret_name}'],
            deleteSecretForAuthenticatedUser: ['DELETE /user/codespaces/secrets/{secret_name}'],
            exportForAuthenticatedUser: ['POST /user/codespaces/{codespace_name}/exports'],
            getCodespacesForUserInOrg: ['GET /orgs/{org}/members/{username}/codespaces'],
            getExportDetailsForAuthenticatedUser: [
                'GET /user/codespaces/{codespace_name}/exports/{export_id}',
            ],
            getForAuthenticatedUser: ['GET /user/codespaces/{codespace_name}'],
            getOrgPublicKey: ['GET /orgs/{org}/codespaces/secrets/public-key'],
            getOrgSecret: ['GET /orgs/{org}/codespaces/secrets/{secret_name}'],
            getPublicKeyForAuthenticatedUser: ['GET /user/codespaces/secrets/public-key'],
            getRepoPublicKey: ['GET /repos/{owner}/{repo}/codespaces/secrets/public-key'],
            getRepoSecret: ['GET /repos/{owner}/{repo}/codespaces/secrets/{secret_name}'],
            getSecretForAuthenticatedUser: ['GET /user/codespaces/secrets/{secret_name}'],
            listDevcontainersInRepositoryForAuthenticatedUser: [
                'GET /repos/{owner}/{repo}/codespaces/devcontainers',
            ],
            listForAuthenticatedUser: ['GET /user/codespaces'],
            listInOrganization: [
                'GET /orgs/{org}/codespaces',
                {},
                { renamedParameters: { org_id: 'org' } },
            ],
            listInRepositoryForAuthenticatedUser: ['GET /repos/{owner}/{repo}/codespaces'],
            listOrgSecrets: ['GET /orgs/{org}/codespaces/secrets'],
            listRepoSecrets: ['GET /repos/{owner}/{repo}/codespaces/secrets'],
            listRepositoriesForSecretForAuthenticatedUser: [
                'GET /user/codespaces/secrets/{secret_name}/repositories',
            ],
            listSecretsForAuthenticatedUser: ['GET /user/codespaces/secrets'],
            listSelectedReposForOrgSecret: [
                'GET /orgs/{org}/codespaces/secrets/{secret_name}/repositories',
            ],
            preFlightWithRepoForAuthenticatedUser: ['GET /repos/{owner}/{repo}/codespaces/new'],
            publishForAuthenticatedUser: ['POST /user/codespaces/{codespace_name}/publish'],
            removeRepositoryForSecretForAuthenticatedUser: [
                'DELETE /user/codespaces/secrets/{secret_name}/repositories/{repository_id}',
            ],
            removeSelectedRepoFromOrgSecret: [
                'DELETE /orgs/{org}/codespaces/secrets/{secret_name}/repositories/{repository_id}',
            ],
            repoMachinesForAuthenticatedUser: ['GET /repos/{owner}/{repo}/codespaces/machines'],
            setRepositoriesForSecretForAuthenticatedUser: [
                'PUT /user/codespaces/secrets/{secret_name}/repositories',
            ],
            setSelectedReposForOrgSecret: [
                'PUT /orgs/{org}/codespaces/secrets/{secret_name}/repositories',
            ],
            startForAuthenticatedUser: ['POST /user/codespaces/{codespace_name}/start'],
            stopForAuthenticatedUser: ['POST /user/codespaces/{codespace_name}/stop'],
            stopInOrganization: [
                'POST /orgs/{org}/members/{username}/codespaces/{codespace_name}/stop',
            ],
            updateForAuthenticatedUser: ['PATCH /user/codespaces/{codespace_name}'],
        },
        copilot: {
            addCopilotSeatsForTeams: ['POST /orgs/{org}/copilot/billing/selected_teams'],
            addCopilotSeatsForUsers: ['POST /orgs/{org}/copilot/billing/selected_users'],
            cancelCopilotSeatAssignmentForTeams: [
                'DELETE /orgs/{org}/copilot/billing/selected_teams',
            ],
            cancelCopilotSeatAssignmentForUsers: [
                'DELETE /orgs/{org}/copilot/billing/selected_users',
            ],
            getCopilotOrganizationDetails: ['GET /orgs/{org}/copilot/billing'],
            getCopilotSeatDetailsForUser: ['GET /orgs/{org}/members/{username}/copilot'],
            listCopilotSeats: ['GET /orgs/{org}/copilot/billing/seats'],
        },
        dependabot: {
            addSelectedRepoToOrgSecret: [
                'PUT /orgs/{org}/dependabot/secrets/{secret_name}/repositories/{repository_id}',
            ],
            createOrUpdateOrgSecret: ['PUT /orgs/{org}/dependabot/secrets/{secret_name}'],
            createOrUpdateRepoSecret: [
                'PUT /repos/{owner}/{repo}/dependabot/secrets/{secret_name}',
            ],
            deleteOrgSecret: ['DELETE /orgs/{org}/dependabot/secrets/{secret_name}'],
            deleteRepoSecret: ['DELETE /repos/{owner}/{repo}/dependabot/secrets/{secret_name}'],
            getAlert: ['GET /repos/{owner}/{repo}/dependabot/alerts/{alert_number}'],
            getOrgPublicKey: ['GET /orgs/{org}/dependabot/secrets/public-key'],
            getOrgSecret: ['GET /orgs/{org}/dependabot/secrets/{secret_name}'],
            getRepoPublicKey: ['GET /repos/{owner}/{repo}/dependabot/secrets/public-key'],
            getRepoSecret: ['GET /repos/{owner}/{repo}/dependabot/secrets/{secret_name}'],
            listAlertsForEnterprise: ['GET /enterprises/{enterprise}/dependabot/alerts'],
            listAlertsForOrg: ['GET /orgs/{org}/dependabot/alerts'],
            listAlertsForRepo: ['GET /repos/{owner}/{repo}/dependabot/alerts'],
            listOrgSecrets: ['GET /orgs/{org}/dependabot/secrets'],
            listRepoSecrets: ['GET /repos/{owner}/{repo}/dependabot/secrets'],
            listSelectedReposForOrgSecret: [
                'GET /orgs/{org}/dependabot/secrets/{secret_name}/repositories',
            ],
            removeSelectedRepoFromOrgSecret: [
                'DELETE /orgs/{org}/dependabot/secrets/{secret_name}/repositories/{repository_id}',
            ],
            setSelectedReposForOrgSecret: [
                'PUT /orgs/{org}/dependabot/secrets/{secret_name}/repositories',
            ],
            updateAlert: ['PATCH /repos/{owner}/{repo}/dependabot/alerts/{alert_number}'],
        },
        dependencyGraph: {
            createRepositorySnapshot: ['POST /repos/{owner}/{repo}/dependency-graph/snapshots'],
            diffRange: ['GET /repos/{owner}/{repo}/dependency-graph/compare/{basehead}'],
            exportSbom: ['GET /repos/{owner}/{repo}/dependency-graph/sbom'],
        },
        emojis: { get: ['GET /emojis'] },
        gists: {
            checkIsStarred: ['GET /gists/{gist_id}/star'],
            create: ['POST /gists'],
            createComment: ['POST /gists/{gist_id}/comments'],
            delete: ['DELETE /gists/{gist_id}'],
            deleteComment: ['DELETE /gists/{gist_id}/comments/{comment_id}'],
            fork: ['POST /gists/{gist_id}/forks'],
            get: ['GET /gists/{gist_id}'],
            getComment: ['GET /gists/{gist_id}/comments/{comment_id}'],
            getRevision: ['GET /gists/{gist_id}/{sha}'],
            list: ['GET /gists'],
            listComments: ['GET /gists/{gist_id}/comments'],
            listCommits: ['GET /gists/{gist_id}/commits'],
            listForUser: ['GET /users/{username}/gists'],
            listForks: ['GET /gists/{gist_id}/forks'],
            listPublic: ['GET /gists/public'],
            listStarred: ['GET /gists/starred'],
            star: ['PUT /gists/{gist_id}/star'],
            unstar: ['DELETE /gists/{gist_id}/star'],
            update: ['PATCH /gists/{gist_id}'],
            updateComment: ['PATCH /gists/{gist_id}/comments/{comment_id}'],
        },
        git: {
            createBlob: ['POST /repos/{owner}/{repo}/git/blobs'],
            createCommit: ['POST /repos/{owner}/{repo}/git/commits'],
            createRef: ['POST /repos/{owner}/{repo}/git/refs'],
            createTag: ['POST /repos/{owner}/{repo}/git/tags'],
            createTree: ['POST /repos/{owner}/{repo}/git/trees'],
            deleteRef: ['DELETE /repos/{owner}/{repo}/git/refs/{ref}'],
            getBlob: ['GET /repos/{owner}/{repo}/git/blobs/{file_sha}'],
            getCommit: ['GET /repos/{owner}/{repo}/git/commits/{commit_sha}'],
            getRef: ['GET /repos/{owner}/{repo}/git/ref/{ref}'],
            getTag: ['GET /repos/{owner}/{repo}/git/tags/{tag_sha}'],
            getTree: ['GET /repos/{owner}/{repo}/git/trees/{tree_sha}'],
            listMatchingRefs: ['GET /repos/{owner}/{repo}/git/matching-refs/{ref}'],
            updateRef: ['PATCH /repos/{owner}/{repo}/git/refs/{ref}'],
        },
        gitignore: {
            getAllTemplates: ['GET /gitignore/templates'],
            getTemplate: ['GET /gitignore/templates/{name}'],
        },
        interactions: {
            getRestrictionsForAuthenticatedUser: ['GET /user/interaction-limits'],
            getRestrictionsForOrg: ['GET /orgs/{org}/interaction-limits'],
            getRestrictionsForRepo: ['GET /repos/{owner}/{repo}/interaction-limits'],
            getRestrictionsForYourPublicRepos: [
                'GET /user/interaction-limits',
                {},
                { renamed: ['interactions', 'getRestrictionsForAuthenticatedUser'] },
            ],
            removeRestrictionsForAuthenticatedUser: ['DELETE /user/interaction-limits'],
            removeRestrictionsForOrg: ['DELETE /orgs/{org}/interaction-limits'],
            removeRestrictionsForRepo: ['DELETE /repos/{owner}/{repo}/interaction-limits'],
            removeRestrictionsForYourPublicRepos: [
                'DELETE /user/interaction-limits',
                {},
                { renamed: ['interactions', 'removeRestrictionsForAuthenticatedUser'] },
            ],
            setRestrictionsForAuthenticatedUser: ['PUT /user/interaction-limits'],
            setRestrictionsForOrg: ['PUT /orgs/{org}/interaction-limits'],
            setRestrictionsForRepo: ['PUT /repos/{owner}/{repo}/interaction-limits'],
            setRestrictionsForYourPublicRepos: [
                'PUT /user/interaction-limits',
                {},
                { renamed: ['interactions', 'setRestrictionsForAuthenticatedUser'] },
            ],
        },
        issues: {
            addAssignees: ['POST /repos/{owner}/{repo}/issues/{issue_number}/assignees'],
            addLabels: ['POST /repos/{owner}/{repo}/issues/{issue_number}/labels'],
            checkUserCanBeAssigned: ['GET /repos/{owner}/{repo}/assignees/{assignee}'],
            checkUserCanBeAssignedToIssue: [
                'GET /repos/{owner}/{repo}/issues/{issue_number}/assignees/{assignee}',
            ],
            create: ['POST /repos/{owner}/{repo}/issues'],
            createComment: ['POST /repos/{owner}/{repo}/issues/{issue_number}/comments'],
            createLabel: ['POST /repos/{owner}/{repo}/labels'],
            createMilestone: ['POST /repos/{owner}/{repo}/milestones'],
            deleteComment: ['DELETE /repos/{owner}/{repo}/issues/comments/{comment_id}'],
            deleteLabel: ['DELETE /repos/{owner}/{repo}/labels/{name}'],
            deleteMilestone: ['DELETE /repos/{owner}/{repo}/milestones/{milestone_number}'],
            get: ['GET /repos/{owner}/{repo}/issues/{issue_number}'],
            getComment: ['GET /repos/{owner}/{repo}/issues/comments/{comment_id}'],
            getEvent: ['GET /repos/{owner}/{repo}/issues/events/{event_id}'],
            getLabel: ['GET /repos/{owner}/{repo}/labels/{name}'],
            getMilestone: ['GET /repos/{owner}/{repo}/milestones/{milestone_number}'],
            list: ['GET /issues'],
            listAssignees: ['GET /repos/{owner}/{repo}/assignees'],
            listComments: ['GET /repos/{owner}/{repo}/issues/{issue_number}/comments'],
            listCommentsForRepo: ['GET /repos/{owner}/{repo}/issues/comments'],
            listEvents: ['GET /repos/{owner}/{repo}/issues/{issue_number}/events'],
            listEventsForRepo: ['GET /repos/{owner}/{repo}/issues/events'],
            listEventsForTimeline: ['GET /repos/{owner}/{repo}/issues/{issue_number}/timeline'],
            listForAuthenticatedUser: ['GET /user/issues'],
            listForOrg: ['GET /orgs/{org}/issues'],
            listForRepo: ['GET /repos/{owner}/{repo}/issues'],
            listLabelsForMilestone: [
                'GET /repos/{owner}/{repo}/milestones/{milestone_number}/labels',
            ],
            listLabelsForRepo: ['GET /repos/{owner}/{repo}/labels'],
            listLabelsOnIssue: ['GET /repos/{owner}/{repo}/issues/{issue_number}/labels'],
            listMilestones: ['GET /repos/{owner}/{repo}/milestones'],
            lock: ['PUT /repos/{owner}/{repo}/issues/{issue_number}/lock'],
            removeAllLabels: ['DELETE /repos/{owner}/{repo}/issues/{issue_number}/labels'],
            removeAssignees: ['DELETE /repos/{owner}/{repo}/issues/{issue_number}/assignees'],
            removeLabel: ['DELETE /repos/{owner}/{repo}/issues/{issue_number}/labels/{name}'],
            setLabels: ['PUT /repos/{owner}/{repo}/issues/{issue_number}/labels'],
            unlock: ['DELETE /repos/{owner}/{repo}/issues/{issue_number}/lock'],
            update: ['PATCH /repos/{owner}/{repo}/issues/{issue_number}'],
            updateComment: ['PATCH /repos/{owner}/{repo}/issues/comments/{comment_id}'],
            updateLabel: ['PATCH /repos/{owner}/{repo}/labels/{name}'],
            updateMilestone: ['PATCH /repos/{owner}/{repo}/milestones/{milestone_number}'],
        },
        licenses: {
            get: ['GET /licenses/{license}'],
            getAllCommonlyUsed: ['GET /licenses'],
            getForRepo: ['GET /repos/{owner}/{repo}/license'],
        },
        markdown: {
            render: ['POST /markdown'],
            renderRaw: [
                'POST /markdown/raw',
                { headers: { 'content-type': 'text/plain; charset=utf-8' } },
            ],
        },
        meta: {
            get: ['GET /meta'],
            getAllVersions: ['GET /versions'],
            getOctocat: ['GET /octocat'],
            getZen: ['GET /zen'],
            root: ['GET /'],
        },
        migrations: {
            cancelImport: [
                'DELETE /repos/{owner}/{repo}/import',
                {},
                {
                    deprecated:
                        'octokit.rest.migrations.cancelImport() is deprecated, see https://docs.github.com/rest/migrations/source-imports#cancel-an-import',
                },
            ],
            deleteArchiveForAuthenticatedUser: ['DELETE /user/migrations/{migration_id}/archive'],
            deleteArchiveForOrg: ['DELETE /orgs/{org}/migrations/{migration_id}/archive'],
            downloadArchiveForOrg: ['GET /orgs/{org}/migrations/{migration_id}/archive'],
            getArchiveForAuthenticatedUser: ['GET /user/migrations/{migration_id}/archive'],
            getCommitAuthors: [
                'GET /repos/{owner}/{repo}/import/authors',
                {},
                {
                    deprecated:
                        'octokit.rest.migrations.getCommitAuthors() is deprecated, see https://docs.github.com/rest/migrations/source-imports#get-commit-authors',
                },
            ],
            getImportStatus: [
                'GET /repos/{owner}/{repo}/import',
                {},
                {
                    deprecated:
                        'octokit.rest.migrations.getImportStatus() is deprecated, see https://docs.github.com/rest/migrations/source-imports#get-an-import-status',
                },
            ],
            getLargeFiles: [
                'GET /repos/{owner}/{repo}/import/large_files',
                {},
                {
                    deprecated:
                        'octokit.rest.migrations.getLargeFiles() is deprecated, see https://docs.github.com/rest/migrations/source-imports#get-large-files',
                },
            ],
            getStatusForAuthenticatedUser: ['GET /user/migrations/{migration_id}'],
            getStatusForOrg: ['GET /orgs/{org}/migrations/{migration_id}'],
            listForAuthenticatedUser: ['GET /user/migrations'],
            listForOrg: ['GET /orgs/{org}/migrations'],
            listReposForAuthenticatedUser: ['GET /user/migrations/{migration_id}/repositories'],
            listReposForOrg: ['GET /orgs/{org}/migrations/{migration_id}/repositories'],
            listReposForUser: [
                'GET /user/migrations/{migration_id}/repositories',
                {},
                { renamed: ['migrations', 'listReposForAuthenticatedUser'] },
            ],
            mapCommitAuthor: [
                'PATCH /repos/{owner}/{repo}/import/authors/{author_id}',
                {},
                {
                    deprecated:
                        'octokit.rest.migrations.mapCommitAuthor() is deprecated, see https://docs.github.com/rest/migrations/source-imports#map-a-commit-author',
                },
            ],
            setLfsPreference: [
                'PATCH /repos/{owner}/{repo}/import/lfs',
                {},
                {
                    deprecated:
                        'octokit.rest.migrations.setLfsPreference() is deprecated, see https://docs.github.com/rest/migrations/source-imports#update-git-lfs-preference',
                },
            ],
            startForAuthenticatedUser: ['POST /user/migrations'],
            startForOrg: ['POST /orgs/{org}/migrations'],
            startImport: [
                'PUT /repos/{owner}/{repo}/import',
                {},
                {
                    deprecated:
                        'octokit.rest.migrations.startImport() is deprecated, see https://docs.github.com/rest/migrations/source-imports#start-an-import',
                },
            ],
            unlockRepoForAuthenticatedUser: [
                'DELETE /user/migrations/{migration_id}/repos/{repo_name}/lock',
            ],
            unlockRepoForOrg: [
                'DELETE /orgs/{org}/migrations/{migration_id}/repos/{repo_name}/lock',
            ],
            updateImport: [
                'PATCH /repos/{owner}/{repo}/import',
                {},
                {
                    deprecated:
                        'octokit.rest.migrations.updateImport() is deprecated, see https://docs.github.com/rest/migrations/source-imports#update-an-import',
                },
            ],
        },
        oidc: {
            getOidcCustomSubTemplateForOrg: ['GET /orgs/{org}/actions/oidc/customization/sub'],
            updateOidcCustomSubTemplateForOrg: ['PUT /orgs/{org}/actions/oidc/customization/sub'],
        },
        orgs: {
            addSecurityManagerTeam: ['PUT /orgs/{org}/security-managers/teams/{team_slug}'],
            assignTeamToOrgRole: ['PUT /orgs/{org}/organization-roles/teams/{team_slug}/{role_id}'],
            assignUserToOrgRole: ['PUT /orgs/{org}/organization-roles/users/{username}/{role_id}'],
            blockUser: ['PUT /orgs/{org}/blocks/{username}'],
            cancelInvitation: ['DELETE /orgs/{org}/invitations/{invitation_id}'],
            checkBlockedUser: ['GET /orgs/{org}/blocks/{username}'],
            checkMembershipForUser: ['GET /orgs/{org}/members/{username}'],
            checkPublicMembershipForUser: ['GET /orgs/{org}/public_members/{username}'],
            convertMemberToOutsideCollaborator: [
                'PUT /orgs/{org}/outside_collaborators/{username}',
            ],
            createCustomOrganizationRole: ['POST /orgs/{org}/organization-roles'],
            createInvitation: ['POST /orgs/{org}/invitations'],
            createOrUpdateCustomProperties: ['PATCH /orgs/{org}/properties/schema'],
            createOrUpdateCustomPropertiesValuesForRepos: ['PATCH /orgs/{org}/properties/values'],
            createOrUpdateCustomProperty: [
                'PUT /orgs/{org}/properties/schema/{custom_property_name}',
            ],
            createWebhook: ['POST /orgs/{org}/hooks'],
            delete: ['DELETE /orgs/{org}'],
            deleteCustomOrganizationRole: ['DELETE /orgs/{org}/organization-roles/{role_id}'],
            deleteWebhook: ['DELETE /orgs/{org}/hooks/{hook_id}'],
            enableOrDisableSecurityProductOnAllOrgRepos: [
                'POST /orgs/{org}/{security_product}/{enablement}',
            ],
            get: ['GET /orgs/{org}'],
            getAllCustomProperties: ['GET /orgs/{org}/properties/schema'],
            getCustomProperty: ['GET /orgs/{org}/properties/schema/{custom_property_name}'],
            getMembershipForAuthenticatedUser: ['GET /user/memberships/orgs/{org}'],
            getMembershipForUser: ['GET /orgs/{org}/memberships/{username}'],
            getOrgRole: ['GET /orgs/{org}/organization-roles/{role_id}'],
            getWebhook: ['GET /orgs/{org}/hooks/{hook_id}'],
            getWebhookConfigForOrg: ['GET /orgs/{org}/hooks/{hook_id}/config'],
            getWebhookDelivery: ['GET /orgs/{org}/hooks/{hook_id}/deliveries/{delivery_id}'],
            list: ['GET /organizations'],
            listAppInstallations: ['GET /orgs/{org}/installations'],
            listBlockedUsers: ['GET /orgs/{org}/blocks'],
            listCustomPropertiesValuesForRepos: ['GET /orgs/{org}/properties/values'],
            listFailedInvitations: ['GET /orgs/{org}/failed_invitations'],
            listForAuthenticatedUser: ['GET /user/orgs'],
            listForUser: ['GET /users/{username}/orgs'],
            listInvitationTeams: ['GET /orgs/{org}/invitations/{invitation_id}/teams'],
            listMembers: ['GET /orgs/{org}/members'],
            listMembershipsForAuthenticatedUser: ['GET /user/memberships/orgs'],
            listOrgRoleTeams: ['GET /orgs/{org}/organization-roles/{role_id}/teams'],
            listOrgRoleUsers: ['GET /orgs/{org}/organization-roles/{role_id}/users'],
            listOrgRoles: ['GET /orgs/{org}/organization-roles'],
            listOrganizationFineGrainedPermissions: [
                'GET /orgs/{org}/organization-fine-grained-permissions',
            ],
            listOutsideCollaborators: ['GET /orgs/{org}/outside_collaborators'],
            listPatGrantRepositories: [
                'GET /orgs/{org}/personal-access-tokens/{pat_id}/repositories',
            ],
            listPatGrantRequestRepositories: [
                'GET /orgs/{org}/personal-access-token-requests/{pat_request_id}/repositories',
            ],
            listPatGrantRequests: ['GET /orgs/{org}/personal-access-token-requests'],
            listPatGrants: ['GET /orgs/{org}/personal-access-tokens'],
            listPendingInvitations: ['GET /orgs/{org}/invitations'],
            listPublicMembers: ['GET /orgs/{org}/public_members'],
            listSecurityManagerTeams: ['GET /orgs/{org}/security-managers'],
            listWebhookDeliveries: ['GET /orgs/{org}/hooks/{hook_id}/deliveries'],
            listWebhooks: ['GET /orgs/{org}/hooks'],
            patchCustomOrganizationRole: ['PATCH /orgs/{org}/organization-roles/{role_id}'],
            pingWebhook: ['POST /orgs/{org}/hooks/{hook_id}/pings'],
            redeliverWebhookDelivery: [
                'POST /orgs/{org}/hooks/{hook_id}/deliveries/{delivery_id}/attempts',
            ],
            removeCustomProperty: ['DELETE /orgs/{org}/properties/schema/{custom_property_name}'],
            removeMember: ['DELETE /orgs/{org}/members/{username}'],
            removeMembershipForUser: ['DELETE /orgs/{org}/memberships/{username}'],
            removeOutsideCollaborator: ['DELETE /orgs/{org}/outside_collaborators/{username}'],
            removePublicMembershipForAuthenticatedUser: [
                'DELETE /orgs/{org}/public_members/{username}',
            ],
            removeSecurityManagerTeam: ['DELETE /orgs/{org}/security-managers/teams/{team_slug}'],
            reviewPatGrantRequest: [
                'POST /orgs/{org}/personal-access-token-requests/{pat_request_id}',
            ],
            reviewPatGrantRequestsInBulk: ['POST /orgs/{org}/personal-access-token-requests'],
            revokeAllOrgRolesTeam: ['DELETE /orgs/{org}/organization-roles/teams/{team_slug}'],
            revokeAllOrgRolesUser: ['DELETE /orgs/{org}/organization-roles/users/{username}'],
            revokeOrgRoleTeam: [
                'DELETE /orgs/{org}/organization-roles/teams/{team_slug}/{role_id}',
            ],
            revokeOrgRoleUser: ['DELETE /orgs/{org}/organization-roles/users/{username}/{role_id}'],
            setMembershipForUser: ['PUT /orgs/{org}/memberships/{username}'],
            setPublicMembershipForAuthenticatedUser: ['PUT /orgs/{org}/public_members/{username}'],
            unblockUser: ['DELETE /orgs/{org}/blocks/{username}'],
            update: ['PATCH /orgs/{org}'],
            updateMembershipForAuthenticatedUser: ['PATCH /user/memberships/orgs/{org}'],
            updatePatAccess: ['POST /orgs/{org}/personal-access-tokens/{pat_id}'],
            updatePatAccesses: ['POST /orgs/{org}/personal-access-tokens'],
            updateWebhook: ['PATCH /orgs/{org}/hooks/{hook_id}'],
            updateWebhookConfigForOrg: ['PATCH /orgs/{org}/hooks/{hook_id}/config'],
        },
        packages: {
            deletePackageForAuthenticatedUser: [
                'DELETE /user/packages/{package_type}/{package_name}',
            ],
            deletePackageForOrg: ['DELETE /orgs/{org}/packages/{package_type}/{package_name}'],
            deletePackageForUser: [
                'DELETE /users/{username}/packages/{package_type}/{package_name}',
            ],
            deletePackageVersionForAuthenticatedUser: [
                'DELETE /user/packages/{package_type}/{package_name}/versions/{package_version_id}',
            ],
            deletePackageVersionForOrg: [
                'DELETE /orgs/{org}/packages/{package_type}/{package_name}/versions/{package_version_id}',
            ],
            deletePackageVersionForUser: [
                'DELETE /users/{username}/packages/{package_type}/{package_name}/versions/{package_version_id}',
            ],
            getAllPackageVersionsForAPackageOwnedByAnOrg: [
                'GET /orgs/{org}/packages/{package_type}/{package_name}/versions',
                {},
                { renamed: ['packages', 'getAllPackageVersionsForPackageOwnedByOrg'] },
            ],
            getAllPackageVersionsForAPackageOwnedByTheAuthenticatedUser: [
                'GET /user/packages/{package_type}/{package_name}/versions',
                {},
                {
                    renamed: [
                        'packages',
                        'getAllPackageVersionsForPackageOwnedByAuthenticatedUser',
                    ],
                },
            ],
            getAllPackageVersionsForPackageOwnedByAuthenticatedUser: [
                'GET /user/packages/{package_type}/{package_name}/versions',
            ],
            getAllPackageVersionsForPackageOwnedByOrg: [
                'GET /orgs/{org}/packages/{package_type}/{package_name}/versions',
            ],
            getAllPackageVersionsForPackageOwnedByUser: [
                'GET /users/{username}/packages/{package_type}/{package_name}/versions',
            ],
            getPackageForAuthenticatedUser: ['GET /user/packages/{package_type}/{package_name}'],
            getPackageForOrganization: ['GET /orgs/{org}/packages/{package_type}/{package_name}'],
            getPackageForUser: ['GET /users/{username}/packages/{package_type}/{package_name}'],
            getPackageVersionForAuthenticatedUser: [
                'GET /user/packages/{package_type}/{package_name}/versions/{package_version_id}',
            ],
            getPackageVersionForOrganization: [
                'GET /orgs/{org}/packages/{package_type}/{package_name}/versions/{package_version_id}',
            ],
            getPackageVersionForUser: [
                'GET /users/{username}/packages/{package_type}/{package_name}/versions/{package_version_id}',
            ],
            listDockerMigrationConflictingPackagesForAuthenticatedUser: [
                'GET /user/docker/conflicts',
            ],
            listDockerMigrationConflictingPackagesForOrganization: [
                'GET /orgs/{org}/docker/conflicts',
            ],
            listDockerMigrationConflictingPackagesForUser: [
                'GET /users/{username}/docker/conflicts',
            ],
            listPackagesForAuthenticatedUser: ['GET /user/packages'],
            listPackagesForOrganization: ['GET /orgs/{org}/packages'],
            listPackagesForUser: ['GET /users/{username}/packages'],
            restorePackageForAuthenticatedUser: [
                'POST /user/packages/{package_type}/{package_name}/restore{?token}',
            ],
            restorePackageForOrg: [
                'POST /orgs/{org}/packages/{package_type}/{package_name}/restore{?token}',
            ],
            restorePackageForUser: [
                'POST /users/{username}/packages/{package_type}/{package_name}/restore{?token}',
            ],
            restorePackageVersionForAuthenticatedUser: [
                'POST /user/packages/{package_type}/{package_name}/versions/{package_version_id}/restore',
            ],
            restorePackageVersionForOrg: [
                'POST /orgs/{org}/packages/{package_type}/{package_name}/versions/{package_version_id}/restore',
            ],
            restorePackageVersionForUser: [
                'POST /users/{username}/packages/{package_type}/{package_name}/versions/{package_version_id}/restore',
            ],
        },
        projects: {
            addCollaborator: ['PUT /projects/{project_id}/collaborators/{username}'],
            createCard: ['POST /projects/columns/{column_id}/cards'],
            createColumn: ['POST /projects/{project_id}/columns'],
            createForAuthenticatedUser: ['POST /user/projects'],
            createForOrg: ['POST /orgs/{org}/projects'],
            createForRepo: ['POST /repos/{owner}/{repo}/projects'],
            delete: ['DELETE /projects/{project_id}'],
            deleteCard: ['DELETE /projects/columns/cards/{card_id}'],
            deleteColumn: ['DELETE /projects/columns/{column_id}'],
            get: ['GET /projects/{project_id}'],
            getCard: ['GET /projects/columns/cards/{card_id}'],
            getColumn: ['GET /projects/columns/{column_id}'],
            getPermissionForUser: [
                'GET /projects/{project_id}/collaborators/{username}/permission',
            ],
            listCards: ['GET /projects/columns/{column_id}/cards'],
            listCollaborators: ['GET /projects/{project_id}/collaborators'],
            listColumns: ['GET /projects/{project_id}/columns'],
            listForOrg: ['GET /orgs/{org}/projects'],
            listForRepo: ['GET /repos/{owner}/{repo}/projects'],
            listForUser: ['GET /users/{username}/projects'],
            moveCard: ['POST /projects/columns/cards/{card_id}/moves'],
            moveColumn: ['POST /projects/columns/{column_id}/moves'],
            removeCollaborator: ['DELETE /projects/{project_id}/collaborators/{username}'],
            update: ['PATCH /projects/{project_id}'],
            updateCard: ['PATCH /projects/columns/cards/{card_id}'],
            updateColumn: ['PATCH /projects/columns/{column_id}'],
        },
        pulls: {
            checkIfMerged: ['GET /repos/{owner}/{repo}/pulls/{pull_number}/merge'],
            create: ['POST /repos/{owner}/{repo}/pulls'],
            createReplyForReviewComment: [
                'POST /repos/{owner}/{repo}/pulls/{pull_number}/comments/{comment_id}/replies',
            ],
            createReview: ['POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews'],
            createReviewComment: ['POST /repos/{owner}/{repo}/pulls/{pull_number}/comments'],
            deletePendingReview: [
                'DELETE /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}',
            ],
            deleteReviewComment: ['DELETE /repos/{owner}/{repo}/pulls/comments/{comment_id}'],
            dismissReview: [
                'PUT /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}/dismissals',
            ],
            get: ['GET /repos/{owner}/{repo}/pulls/{pull_number}'],
            getReview: ['GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}'],
            getReviewComment: ['GET /repos/{owner}/{repo}/pulls/comments/{comment_id}'],
            list: ['GET /repos/{owner}/{repo}/pulls'],
            listCommentsForReview: [
                'GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}/comments',
            ],
            listCommits: ['GET /repos/{owner}/{repo}/pulls/{pull_number}/commits'],
            listFiles: ['GET /repos/{owner}/{repo}/pulls/{pull_number}/files'],
            listRequestedReviewers: [
                'GET /repos/{owner}/{repo}/pulls/{pull_number}/requested_reviewers',
            ],
            listReviewComments: ['GET /repos/{owner}/{repo}/pulls/{pull_number}/comments'],
            listReviewCommentsForRepo: ['GET /repos/{owner}/{repo}/pulls/comments'],
            listReviews: ['GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews'],
            merge: ['PUT /repos/{owner}/{repo}/pulls/{pull_number}/merge'],
            removeRequestedReviewers: [
                'DELETE /repos/{owner}/{repo}/pulls/{pull_number}/requested_reviewers',
            ],
            requestReviewers: [
                'POST /repos/{owner}/{repo}/pulls/{pull_number}/requested_reviewers',
            ],
            submitReview: [
                'POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}/events',
            ],
            update: ['PATCH /repos/{owner}/{repo}/pulls/{pull_number}'],
            updateBranch: ['PUT /repos/{owner}/{repo}/pulls/{pull_number}/update-branch'],
            updateReview: ['PUT /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}'],
            updateReviewComment: ['PATCH /repos/{owner}/{repo}/pulls/comments/{comment_id}'],
        },
        rateLimit: { get: ['GET /rate_limit'] },
        reactions: {
            createForCommitComment: ['POST /repos/{owner}/{repo}/comments/{comment_id}/reactions'],
            createForIssue: ['POST /repos/{owner}/{repo}/issues/{issue_number}/reactions'],
            createForIssueComment: [
                'POST /repos/{owner}/{repo}/issues/comments/{comment_id}/reactions',
            ],
            createForPullRequestReviewComment: [
                'POST /repos/{owner}/{repo}/pulls/comments/{comment_id}/reactions',
            ],
            createForRelease: ['POST /repos/{owner}/{repo}/releases/{release_id}/reactions'],
            createForTeamDiscussionCommentInOrg: [
                'POST /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}/reactions',
            ],
            createForTeamDiscussionInOrg: [
                'POST /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/reactions',
            ],
            deleteForCommitComment: [
                'DELETE /repos/{owner}/{repo}/comments/{comment_id}/reactions/{reaction_id}',
            ],
            deleteForIssue: [
                'DELETE /repos/{owner}/{repo}/issues/{issue_number}/reactions/{reaction_id}',
            ],
            deleteForIssueComment: [
                'DELETE /repos/{owner}/{repo}/issues/comments/{comment_id}/reactions/{reaction_id}',
            ],
            deleteForPullRequestComment: [
                'DELETE /repos/{owner}/{repo}/pulls/comments/{comment_id}/reactions/{reaction_id}',
            ],
            deleteForRelease: [
                'DELETE /repos/{owner}/{repo}/releases/{release_id}/reactions/{reaction_id}',
            ],
            deleteForTeamDiscussion: [
                'DELETE /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/reactions/{reaction_id}',
            ],
            deleteForTeamDiscussionComment: [
                'DELETE /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}/reactions/{reaction_id}',
            ],
            listForCommitComment: ['GET /repos/{owner}/{repo}/comments/{comment_id}/reactions'],
            listForIssue: ['GET /repos/{owner}/{repo}/issues/{issue_number}/reactions'],
            listForIssueComment: [
                'GET /repos/{owner}/{repo}/issues/comments/{comment_id}/reactions',
            ],
            listForPullRequestReviewComment: [
                'GET /repos/{owner}/{repo}/pulls/comments/{comment_id}/reactions',
            ],
            listForRelease: ['GET /repos/{owner}/{repo}/releases/{release_id}/reactions'],
            listForTeamDiscussionCommentInOrg: [
                'GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}/reactions',
            ],
            listForTeamDiscussionInOrg: [
                'GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/reactions',
            ],
        },
        repos: {
            acceptInvitation: [
                'PATCH /user/repository_invitations/{invitation_id}',
                {},
                { renamed: ['repos', 'acceptInvitationForAuthenticatedUser'] },
            ],
            acceptInvitationForAuthenticatedUser: [
                'PATCH /user/repository_invitations/{invitation_id}',
            ],
            addAppAccessRestrictions: [
                'POST /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/apps',
                {},
                { mapToData: 'apps' },
            ],
            addCollaborator: ['PUT /repos/{owner}/{repo}/collaborators/{username}'],
            addStatusCheckContexts: [
                'POST /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks/contexts',
                {},
                { mapToData: 'contexts' },
            ],
            addTeamAccessRestrictions: [
                'POST /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/teams',
                {},
                { mapToData: 'teams' },
            ],
            addUserAccessRestrictions: [
                'POST /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/users',
                {},
                { mapToData: 'users' },
            ],
            cancelPagesDeployment: [
                'POST /repos/{owner}/{repo}/pages/deployments/{pages_deployment_id}/cancel',
            ],
            checkAutomatedSecurityFixes: ['GET /repos/{owner}/{repo}/automated-security-fixes'],
            checkCollaborator: ['GET /repos/{owner}/{repo}/collaborators/{username}'],
            checkVulnerabilityAlerts: ['GET /repos/{owner}/{repo}/vulnerability-alerts'],
            codeownersErrors: ['GET /repos/{owner}/{repo}/codeowners/errors'],
            compareCommits: ['GET /repos/{owner}/{repo}/compare/{base}...{head}'],
            compareCommitsWithBasehead: ['GET /repos/{owner}/{repo}/compare/{basehead}'],
            createAutolink: ['POST /repos/{owner}/{repo}/autolinks'],
            createCommitComment: ['POST /repos/{owner}/{repo}/commits/{commit_sha}/comments'],
            createCommitSignatureProtection: [
                'POST /repos/{owner}/{repo}/branches/{branch}/protection/required_signatures',
            ],
            createCommitStatus: ['POST /repos/{owner}/{repo}/statuses/{sha}'],
            createDeployKey: ['POST /repos/{owner}/{repo}/keys'],
            createDeployment: ['POST /repos/{owner}/{repo}/deployments'],
            createDeploymentBranchPolicy: [
                'POST /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies',
            ],
            createDeploymentProtectionRule: [
                'POST /repos/{owner}/{repo}/environments/{environment_name}/deployment_protection_rules',
            ],
            createDeploymentStatus: [
                'POST /repos/{owner}/{repo}/deployments/{deployment_id}/statuses',
            ],
            createDispatchEvent: ['POST /repos/{owner}/{repo}/dispatches'],
            createForAuthenticatedUser: ['POST /user/repos'],
            createFork: ['POST /repos/{owner}/{repo}/forks'],
            createInOrg: ['POST /orgs/{org}/repos'],
            createOrUpdateCustomPropertiesValues: ['PATCH /repos/{owner}/{repo}/properties/values'],
            createOrUpdateEnvironment: [
                'PUT /repos/{owner}/{repo}/environments/{environment_name}',
            ],
            createOrUpdateFileContents: ['PUT /repos/{owner}/{repo}/contents/{path}'],
            createOrgRuleset: ['POST /orgs/{org}/rulesets'],
            createPagesDeployment: ['POST /repos/{owner}/{repo}/pages/deployments'],
            createPagesSite: ['POST /repos/{owner}/{repo}/pages'],
            createRelease: ['POST /repos/{owner}/{repo}/releases'],
            createRepoRuleset: ['POST /repos/{owner}/{repo}/rulesets'],
            createTagProtection: ['POST /repos/{owner}/{repo}/tags/protection'],
            createUsingTemplate: ['POST /repos/{template_owner}/{template_repo}/generate'],
            createWebhook: ['POST /repos/{owner}/{repo}/hooks'],
            declineInvitation: [
                'DELETE /user/repository_invitations/{invitation_id}',
                {},
                { renamed: ['repos', 'declineInvitationForAuthenticatedUser'] },
            ],
            declineInvitationForAuthenticatedUser: [
                'DELETE /user/repository_invitations/{invitation_id}',
            ],
            delete: ['DELETE /repos/{owner}/{repo}'],
            deleteAccessRestrictions: [
                'DELETE /repos/{owner}/{repo}/branches/{branch}/protection/restrictions',
            ],
            deleteAdminBranchProtection: [
                'DELETE /repos/{owner}/{repo}/branches/{branch}/protection/enforce_admins',
            ],
            deleteAnEnvironment: ['DELETE /repos/{owner}/{repo}/environments/{environment_name}'],
            deleteAutolink: ['DELETE /repos/{owner}/{repo}/autolinks/{autolink_id}'],
            deleteBranchProtection: ['DELETE /repos/{owner}/{repo}/branches/{branch}/protection'],
            deleteCommitComment: ['DELETE /repos/{owner}/{repo}/comments/{comment_id}'],
            deleteCommitSignatureProtection: [
                'DELETE /repos/{owner}/{repo}/branches/{branch}/protection/required_signatures',
            ],
            deleteDeployKey: ['DELETE /repos/{owner}/{repo}/keys/{key_id}'],
            deleteDeployment: ['DELETE /repos/{owner}/{repo}/deployments/{deployment_id}'],
            deleteDeploymentBranchPolicy: [
                'DELETE /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies/{branch_policy_id}',
            ],
            deleteFile: ['DELETE /repos/{owner}/{repo}/contents/{path}'],
            deleteInvitation: ['DELETE /repos/{owner}/{repo}/invitations/{invitation_id}'],
            deleteOrgRuleset: ['DELETE /orgs/{org}/rulesets/{ruleset_id}'],
            deletePagesSite: ['DELETE /repos/{owner}/{repo}/pages'],
            deletePullRequestReviewProtection: [
                'DELETE /repos/{owner}/{repo}/branches/{branch}/protection/required_pull_request_reviews',
            ],
            deleteRelease: ['DELETE /repos/{owner}/{repo}/releases/{release_id}'],
            deleteReleaseAsset: ['DELETE /repos/{owner}/{repo}/releases/assets/{asset_id}'],
            deleteRepoRuleset: ['DELETE /repos/{owner}/{repo}/rulesets/{ruleset_id}'],
            deleteTagProtection: [
                'DELETE /repos/{owner}/{repo}/tags/protection/{tag_protection_id}',
            ],
            deleteWebhook: ['DELETE /repos/{owner}/{repo}/hooks/{hook_id}'],
            disableAutomatedSecurityFixes: [
                'DELETE /repos/{owner}/{repo}/automated-security-fixes',
            ],
            disableDeploymentProtectionRule: [
                'DELETE /repos/{owner}/{repo}/environments/{environment_name}/deployment_protection_rules/{protection_rule_id}',
            ],
            disablePrivateVulnerabilityReporting: [
                'DELETE /repos/{owner}/{repo}/private-vulnerability-reporting',
            ],
            disableVulnerabilityAlerts: ['DELETE /repos/{owner}/{repo}/vulnerability-alerts'],
            downloadArchive: [
                'GET /repos/{owner}/{repo}/zipball/{ref}',
                {},
                { renamed: ['repos', 'downloadZipballArchive'] },
            ],
            downloadTarballArchive: ['GET /repos/{owner}/{repo}/tarball/{ref}'],
            downloadZipballArchive: ['GET /repos/{owner}/{repo}/zipball/{ref}'],
            enableAutomatedSecurityFixes: ['PUT /repos/{owner}/{repo}/automated-security-fixes'],
            enablePrivateVulnerabilityReporting: [
                'PUT /repos/{owner}/{repo}/private-vulnerability-reporting',
            ],
            enableVulnerabilityAlerts: ['PUT /repos/{owner}/{repo}/vulnerability-alerts'],
            generateReleaseNotes: ['POST /repos/{owner}/{repo}/releases/generate-notes'],
            get: ['GET /repos/{owner}/{repo}'],
            getAccessRestrictions: [
                'GET /repos/{owner}/{repo}/branches/{branch}/protection/restrictions',
            ],
            getAdminBranchProtection: [
                'GET /repos/{owner}/{repo}/branches/{branch}/protection/enforce_admins',
            ],
            getAllDeploymentProtectionRules: [
                'GET /repos/{owner}/{repo}/environments/{environment_name}/deployment_protection_rules',
            ],
            getAllEnvironments: ['GET /repos/{owner}/{repo}/environments'],
            getAllStatusCheckContexts: [
                'GET /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks/contexts',
            ],
            getAllTopics: ['GET /repos/{owner}/{repo}/topics'],
            getAppsWithAccessToProtectedBranch: [
                'GET /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/apps',
            ],
            getAutolink: ['GET /repos/{owner}/{repo}/autolinks/{autolink_id}'],
            getBranch: ['GET /repos/{owner}/{repo}/branches/{branch}'],
            getBranchProtection: ['GET /repos/{owner}/{repo}/branches/{branch}/protection'],
            getBranchRules: ['GET /repos/{owner}/{repo}/rules/branches/{branch}'],
            getClones: ['GET /repos/{owner}/{repo}/traffic/clones'],
            getCodeFrequencyStats: ['GET /repos/{owner}/{repo}/stats/code_frequency'],
            getCollaboratorPermissionLevel: [
                'GET /repos/{owner}/{repo}/collaborators/{username}/permission',
            ],
            getCombinedStatusForRef: ['GET /repos/{owner}/{repo}/commits/{ref}/status'],
            getCommit: ['GET /repos/{owner}/{repo}/commits/{ref}'],
            getCommitActivityStats: ['GET /repos/{owner}/{repo}/stats/commit_activity'],
            getCommitComment: ['GET /repos/{owner}/{repo}/comments/{comment_id}'],
            getCommitSignatureProtection: [
                'GET /repos/{owner}/{repo}/branches/{branch}/protection/required_signatures',
            ],
            getCommunityProfileMetrics: ['GET /repos/{owner}/{repo}/community/profile'],
            getContent: ['GET /repos/{owner}/{repo}/contents/{path}'],
            getContributorsStats: ['GET /repos/{owner}/{repo}/stats/contributors'],
            getCustomDeploymentProtectionRule: [
                'GET /repos/{owner}/{repo}/environments/{environment_name}/deployment_protection_rules/{protection_rule_id}',
            ],
            getCustomPropertiesValues: ['GET /repos/{owner}/{repo}/properties/values'],
            getDeployKey: ['GET /repos/{owner}/{repo}/keys/{key_id}'],
            getDeployment: ['GET /repos/{owner}/{repo}/deployments/{deployment_id}'],
            getDeploymentBranchPolicy: [
                'GET /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies/{branch_policy_id}',
            ],
            getDeploymentStatus: [
                'GET /repos/{owner}/{repo}/deployments/{deployment_id}/statuses/{status_id}',
            ],
            getEnvironment: ['GET /repos/{owner}/{repo}/environments/{environment_name}'],
            getLatestPagesBuild: ['GET /repos/{owner}/{repo}/pages/builds/latest'],
            getLatestRelease: ['GET /repos/{owner}/{repo}/releases/latest'],
            getOrgRuleSuite: ['GET /orgs/{org}/rulesets/rule-suites/{rule_suite_id}'],
            getOrgRuleSuites: ['GET /orgs/{org}/rulesets/rule-suites'],
            getOrgRuleset: ['GET /orgs/{org}/rulesets/{ruleset_id}'],
            getOrgRulesets: ['GET /orgs/{org}/rulesets'],
            getPages: ['GET /repos/{owner}/{repo}/pages'],
            getPagesBuild: ['GET /repos/{owner}/{repo}/pages/builds/{build_id}'],
            getPagesDeployment: [
                'GET /repos/{owner}/{repo}/pages/deployments/{pages_deployment_id}',
            ],
            getPagesHealthCheck: ['GET /repos/{owner}/{repo}/pages/health'],
            getParticipationStats: ['GET /repos/{owner}/{repo}/stats/participation'],
            getPullRequestReviewProtection: [
                'GET /repos/{owner}/{repo}/branches/{branch}/protection/required_pull_request_reviews',
            ],
            getPunchCardStats: ['GET /repos/{owner}/{repo}/stats/punch_card'],
            getReadme: ['GET /repos/{owner}/{repo}/readme'],
            getReadmeInDirectory: ['GET /repos/{owner}/{repo}/readme/{dir}'],
            getRelease: ['GET /repos/{owner}/{repo}/releases/{release_id}'],
            getReleaseAsset: ['GET /repos/{owner}/{repo}/releases/assets/{asset_id}'],
            getReleaseByTag: ['GET /repos/{owner}/{repo}/releases/tags/{tag}'],
            getRepoRuleSuite: ['GET /repos/{owner}/{repo}/rulesets/rule-suites/{rule_suite_id}'],
            getRepoRuleSuites: ['GET /repos/{owner}/{repo}/rulesets/rule-suites'],
            getRepoRuleset: ['GET /repos/{owner}/{repo}/rulesets/{ruleset_id}'],
            getRepoRulesets: ['GET /repos/{owner}/{repo}/rulesets'],
            getStatusChecksProtection: [
                'GET /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks',
            ],
            getTeamsWithAccessToProtectedBranch: [
                'GET /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/teams',
            ],
            getTopPaths: ['GET /repos/{owner}/{repo}/traffic/popular/paths'],
            getTopReferrers: ['GET /repos/{owner}/{repo}/traffic/popular/referrers'],
            getUsersWithAccessToProtectedBranch: [
                'GET /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/users',
            ],
            getViews: ['GET /repos/{owner}/{repo}/traffic/views'],
            getWebhook: ['GET /repos/{owner}/{repo}/hooks/{hook_id}'],
            getWebhookConfigForRepo: ['GET /repos/{owner}/{repo}/hooks/{hook_id}/config'],
            getWebhookDelivery: [
                'GET /repos/{owner}/{repo}/hooks/{hook_id}/deliveries/{delivery_id}',
            ],
            listActivities: ['GET /repos/{owner}/{repo}/activity'],
            listAutolinks: ['GET /repos/{owner}/{repo}/autolinks'],
            listBranches: ['GET /repos/{owner}/{repo}/branches'],
            listBranchesForHeadCommit: [
                'GET /repos/{owner}/{repo}/commits/{commit_sha}/branches-where-head',
            ],
            listCollaborators: ['GET /repos/{owner}/{repo}/collaborators'],
            listCommentsForCommit: ['GET /repos/{owner}/{repo}/commits/{commit_sha}/comments'],
            listCommitCommentsForRepo: ['GET /repos/{owner}/{repo}/comments'],
            listCommitStatusesForRef: ['GET /repos/{owner}/{repo}/commits/{ref}/statuses'],
            listCommits: ['GET /repos/{owner}/{repo}/commits'],
            listContributors: ['GET /repos/{owner}/{repo}/contributors'],
            listCustomDeploymentRuleIntegrations: [
                'GET /repos/{owner}/{repo}/environments/{environment_name}/deployment_protection_rules/apps',
            ],
            listDeployKeys: ['GET /repos/{owner}/{repo}/keys'],
            listDeploymentBranchPolicies: [
                'GET /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies',
            ],
            listDeploymentStatuses: [
                'GET /repos/{owner}/{repo}/deployments/{deployment_id}/statuses',
            ],
            listDeployments: ['GET /repos/{owner}/{repo}/deployments'],
            listForAuthenticatedUser: ['GET /user/repos'],
            listForOrg: ['GET /orgs/{org}/repos'],
            listForUser: ['GET /users/{username}/repos'],
            listForks: ['GET /repos/{owner}/{repo}/forks'],
            listInvitations: ['GET /repos/{owner}/{repo}/invitations'],
            listInvitationsForAuthenticatedUser: ['GET /user/repository_invitations'],
            listLanguages: ['GET /repos/{owner}/{repo}/languages'],
            listPagesBuilds: ['GET /repos/{owner}/{repo}/pages/builds'],
            listPublic: ['GET /repositories'],
            listPullRequestsAssociatedWithCommit: [
                'GET /repos/{owner}/{repo}/commits/{commit_sha}/pulls',
            ],
            listReleaseAssets: ['GET /repos/{owner}/{repo}/releases/{release_id}/assets'],
            listReleases: ['GET /repos/{owner}/{repo}/releases'],
            listTagProtection: ['GET /repos/{owner}/{repo}/tags/protection'],
            listTags: ['GET /repos/{owner}/{repo}/tags'],
            listTeams: ['GET /repos/{owner}/{repo}/teams'],
            listWebhookDeliveries: ['GET /repos/{owner}/{repo}/hooks/{hook_id}/deliveries'],
            listWebhooks: ['GET /repos/{owner}/{repo}/hooks'],
            merge: ['POST /repos/{owner}/{repo}/merges'],
            mergeUpstream: ['POST /repos/{owner}/{repo}/merge-upstream'],
            pingWebhook: ['POST /repos/{owner}/{repo}/hooks/{hook_id}/pings'],
            redeliverWebhookDelivery: [
                'POST /repos/{owner}/{repo}/hooks/{hook_id}/deliveries/{delivery_id}/attempts',
            ],
            removeAppAccessRestrictions: [
                'DELETE /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/apps',
                {},
                { mapToData: 'apps' },
            ],
            removeCollaborator: ['DELETE /repos/{owner}/{repo}/collaborators/{username}'],
            removeStatusCheckContexts: [
                'DELETE /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks/contexts',
                {},
                { mapToData: 'contexts' },
            ],
            removeStatusCheckProtection: [
                'DELETE /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks',
            ],
            removeTeamAccessRestrictions: [
                'DELETE /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/teams',
                {},
                { mapToData: 'teams' },
            ],
            removeUserAccessRestrictions: [
                'DELETE /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/users',
                {},
                { mapToData: 'users' },
            ],
            renameBranch: ['POST /repos/{owner}/{repo}/branches/{branch}/rename'],
            replaceAllTopics: ['PUT /repos/{owner}/{repo}/topics'],
            requestPagesBuild: ['POST /repos/{owner}/{repo}/pages/builds'],
            setAdminBranchProtection: [
                'POST /repos/{owner}/{repo}/branches/{branch}/protection/enforce_admins',
            ],
            setAppAccessRestrictions: [
                'PUT /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/apps',
                {},
                { mapToData: 'apps' },
            ],
            setStatusCheckContexts: [
                'PUT /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks/contexts',
                {},
                { mapToData: 'contexts' },
            ],
            setTeamAccessRestrictions: [
                'PUT /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/teams',
                {},
                { mapToData: 'teams' },
            ],
            setUserAccessRestrictions: [
                'PUT /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/users',
                {},
                { mapToData: 'users' },
            ],
            testPushWebhook: ['POST /repos/{owner}/{repo}/hooks/{hook_id}/tests'],
            transfer: ['POST /repos/{owner}/{repo}/transfer'],
            update: ['PATCH /repos/{owner}/{repo}'],
            updateBranchProtection: ['PUT /repos/{owner}/{repo}/branches/{branch}/protection'],
            updateCommitComment: ['PATCH /repos/{owner}/{repo}/comments/{comment_id}'],
            updateDeploymentBranchPolicy: [
                'PUT /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies/{branch_policy_id}',
            ],
            updateInformationAboutPagesSite: ['PUT /repos/{owner}/{repo}/pages'],
            updateInvitation: ['PATCH /repos/{owner}/{repo}/invitations/{invitation_id}'],
            updateOrgRuleset: ['PUT /orgs/{org}/rulesets/{ruleset_id}'],
            updatePullRequestReviewProtection: [
                'PATCH /repos/{owner}/{repo}/branches/{branch}/protection/required_pull_request_reviews',
            ],
            updateRelease: ['PATCH /repos/{owner}/{repo}/releases/{release_id}'],
            updateReleaseAsset: ['PATCH /repos/{owner}/{repo}/releases/assets/{asset_id}'],
            updateRepoRuleset: ['PUT /repos/{owner}/{repo}/rulesets/{ruleset_id}'],
            updateStatusCheckPotection: [
                'PATCH /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks',
                {},
                { renamed: ['repos', 'updateStatusCheckProtection'] },
            ],
            updateStatusCheckProtection: [
                'PATCH /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks',
            ],
            updateWebhook: ['PATCH /repos/{owner}/{repo}/hooks/{hook_id}'],
            updateWebhookConfigForRepo: ['PATCH /repos/{owner}/{repo}/hooks/{hook_id}/config'],
            uploadReleaseAsset: [
                'POST /repos/{owner}/{repo}/releases/{release_id}/assets{?name,label}',
                { baseUrl: 'https://uploads.github.com' },
            ],
        },
        search: {
            code: ['GET /search/code'],
            commits: ['GET /search/commits'],
            issuesAndPullRequests: ['GET /search/issues'],
            labels: ['GET /search/labels'],
            repos: ['GET /search/repositories'],
            topics: ['GET /search/topics'],
            users: ['GET /search/users'],
        },
        secretScanning: {
            getAlert: ['GET /repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}'],
            listAlertsForEnterprise: ['GET /enterprises/{enterprise}/secret-scanning/alerts'],
            listAlertsForOrg: ['GET /orgs/{org}/secret-scanning/alerts'],
            listAlertsForRepo: ['GET /repos/{owner}/{repo}/secret-scanning/alerts'],
            listLocationsForAlert: [
                'GET /repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}/locations',
            ],
            updateAlert: ['PATCH /repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}'],
        },
        securityAdvisories: {
            createFork: ['POST /repos/{owner}/{repo}/security-advisories/{ghsa_id}/forks'],
            createPrivateVulnerabilityReport: [
                'POST /repos/{owner}/{repo}/security-advisories/reports',
            ],
            createRepositoryAdvisory: ['POST /repos/{owner}/{repo}/security-advisories'],
            createRepositoryAdvisoryCveRequest: [
                'POST /repos/{owner}/{repo}/security-advisories/{ghsa_id}/cve',
            ],
            getGlobalAdvisory: ['GET /advisories/{ghsa_id}'],
            getRepositoryAdvisory: ['GET /repos/{owner}/{repo}/security-advisories/{ghsa_id}'],
            listGlobalAdvisories: ['GET /advisories'],
            listOrgRepositoryAdvisories: ['GET /orgs/{org}/security-advisories'],
            listRepositoryAdvisories: ['GET /repos/{owner}/{repo}/security-advisories'],
            updateRepositoryAdvisory: ['PATCH /repos/{owner}/{repo}/security-advisories/{ghsa_id}'],
        },
        teams: {
            addOrUpdateMembershipForUserInOrg: [
                'PUT /orgs/{org}/teams/{team_slug}/memberships/{username}',
            ],
            addOrUpdateProjectPermissionsInOrg: [
                'PUT /orgs/{org}/teams/{team_slug}/projects/{project_id}',
            ],
            addOrUpdateRepoPermissionsInOrg: [
                'PUT /orgs/{org}/teams/{team_slug}/repos/{owner}/{repo}',
            ],
            checkPermissionsForProjectInOrg: [
                'GET /orgs/{org}/teams/{team_slug}/projects/{project_id}',
            ],
            checkPermissionsForRepoInOrg: [
                'GET /orgs/{org}/teams/{team_slug}/repos/{owner}/{repo}',
            ],
            create: ['POST /orgs/{org}/teams'],
            createDiscussionCommentInOrg: [
                'POST /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments',
            ],
            createDiscussionInOrg: ['POST /orgs/{org}/teams/{team_slug}/discussions'],
            deleteDiscussionCommentInOrg: [
                'DELETE /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}',
            ],
            deleteDiscussionInOrg: [
                'DELETE /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}',
            ],
            deleteInOrg: ['DELETE /orgs/{org}/teams/{team_slug}'],
            getByName: ['GET /orgs/{org}/teams/{team_slug}'],
            getDiscussionCommentInOrg: [
                'GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}',
            ],
            getDiscussionInOrg: [
                'GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}',
            ],
            getMembershipForUserInOrg: ['GET /orgs/{org}/teams/{team_slug}/memberships/{username}'],
            list: ['GET /orgs/{org}/teams'],
            listChildInOrg: ['GET /orgs/{org}/teams/{team_slug}/teams'],
            listDiscussionCommentsInOrg: [
                'GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments',
            ],
            listDiscussionsInOrg: ['GET /orgs/{org}/teams/{team_slug}/discussions'],
            listForAuthenticatedUser: ['GET /user/teams'],
            listMembersInOrg: ['GET /orgs/{org}/teams/{team_slug}/members'],
            listPendingInvitationsInOrg: ['GET /orgs/{org}/teams/{team_slug}/invitations'],
            listProjectsInOrg: ['GET /orgs/{org}/teams/{team_slug}/projects'],
            listReposInOrg: ['GET /orgs/{org}/teams/{team_slug}/repos'],
            removeMembershipForUserInOrg: [
                'DELETE /orgs/{org}/teams/{team_slug}/memberships/{username}',
            ],
            removeProjectInOrg: ['DELETE /orgs/{org}/teams/{team_slug}/projects/{project_id}'],
            removeRepoInOrg: ['DELETE /orgs/{org}/teams/{team_slug}/repos/{owner}/{repo}'],
            updateDiscussionCommentInOrg: [
                'PATCH /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}',
            ],
            updateDiscussionInOrg: [
                'PATCH /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}',
            ],
            updateInOrg: ['PATCH /orgs/{org}/teams/{team_slug}'],
        },
        users: {
            addEmailForAuthenticated: [
                'POST /user/emails',
                {},
                { renamed: ['users', 'addEmailForAuthenticatedUser'] },
            ],
            addEmailForAuthenticatedUser: ['POST /user/emails'],
            addSocialAccountForAuthenticatedUser: ['POST /user/social_accounts'],
            block: ['PUT /user/blocks/{username}'],
            checkBlocked: ['GET /user/blocks/{username}'],
            checkFollowingForUser: ['GET /users/{username}/following/{target_user}'],
            checkPersonIsFollowedByAuthenticated: ['GET /user/following/{username}'],
            createGpgKeyForAuthenticated: [
                'POST /user/gpg_keys',
                {},
                { renamed: ['users', 'createGpgKeyForAuthenticatedUser'] },
            ],
            createGpgKeyForAuthenticatedUser: ['POST /user/gpg_keys'],
            createPublicSshKeyForAuthenticated: [
                'POST /user/keys',
                {},
                { renamed: ['users', 'createPublicSshKeyForAuthenticatedUser'] },
            ],
            createPublicSshKeyForAuthenticatedUser: ['POST /user/keys'],
            createSshSigningKeyForAuthenticatedUser: ['POST /user/ssh_signing_keys'],
            deleteEmailForAuthenticated: [
                'DELETE /user/emails',
                {},
                { renamed: ['users', 'deleteEmailForAuthenticatedUser'] },
            ],
            deleteEmailForAuthenticatedUser: ['DELETE /user/emails'],
            deleteGpgKeyForAuthenticated: [
                'DELETE /user/gpg_keys/{gpg_key_id}',
                {},
                { renamed: ['users', 'deleteGpgKeyForAuthenticatedUser'] },
            ],
            deleteGpgKeyForAuthenticatedUser: ['DELETE /user/gpg_keys/{gpg_key_id}'],
            deletePublicSshKeyForAuthenticated: [
                'DELETE /user/keys/{key_id}',
                {},
                { renamed: ['users', 'deletePublicSshKeyForAuthenticatedUser'] },
            ],
            deletePublicSshKeyForAuthenticatedUser: ['DELETE /user/keys/{key_id}'],
            deleteSocialAccountForAuthenticatedUser: ['DELETE /user/social_accounts'],
            deleteSshSigningKeyForAuthenticatedUser: [
                'DELETE /user/ssh_signing_keys/{ssh_signing_key_id}',
            ],
            follow: ['PUT /user/following/{username}'],
            getAuthenticated: ['GET /user'],
            getByUsername: ['GET /users/{username}'],
            getContextForUser: ['GET /users/{username}/hovercard'],
            getGpgKeyForAuthenticated: [
                'GET /user/gpg_keys/{gpg_key_id}',
                {},
                { renamed: ['users', 'getGpgKeyForAuthenticatedUser'] },
            ],
            getGpgKeyForAuthenticatedUser: ['GET /user/gpg_keys/{gpg_key_id}'],
            getPublicSshKeyForAuthenticated: [
                'GET /user/keys/{key_id}',
                {},
                { renamed: ['users', 'getPublicSshKeyForAuthenticatedUser'] },
            ],
            getPublicSshKeyForAuthenticatedUser: ['GET /user/keys/{key_id}'],
            getSshSigningKeyForAuthenticatedUser: [
                'GET /user/ssh_signing_keys/{ssh_signing_key_id}',
            ],
            list: ['GET /users'],
            listBlockedByAuthenticated: [
                'GET /user/blocks',
                {},
                { renamed: ['users', 'listBlockedByAuthenticatedUser'] },
            ],
            listBlockedByAuthenticatedUser: ['GET /user/blocks'],
            listEmailsForAuthenticated: [
                'GET /user/emails',
                {},
                { renamed: ['users', 'listEmailsForAuthenticatedUser'] },
            ],
            listEmailsForAuthenticatedUser: ['GET /user/emails'],
            listFollowedByAuthenticated: [
                'GET /user/following',
                {},
                { renamed: ['users', 'listFollowedByAuthenticatedUser'] },
            ],
            listFollowedByAuthenticatedUser: ['GET /user/following'],
            listFollowersForAuthenticatedUser: ['GET /user/followers'],
            listFollowersForUser: ['GET /users/{username}/followers'],
            listFollowingForUser: ['GET /users/{username}/following'],
            listGpgKeysForAuthenticated: [
                'GET /user/gpg_keys',
                {},
                { renamed: ['users', 'listGpgKeysForAuthenticatedUser'] },
            ],
            listGpgKeysForAuthenticatedUser: ['GET /user/gpg_keys'],
            listGpgKeysForUser: ['GET /users/{username}/gpg_keys'],
            listPublicEmailsForAuthenticated: [
                'GET /user/public_emails',
                {},
                { renamed: ['users', 'listPublicEmailsForAuthenticatedUser'] },
            ],
            listPublicEmailsForAuthenticatedUser: ['GET /user/public_emails'],
            listPublicKeysForUser: ['GET /users/{username}/keys'],
            listPublicSshKeysForAuthenticated: [
                'GET /user/keys',
                {},
                { renamed: ['users', 'listPublicSshKeysForAuthenticatedUser'] },
            ],
            listPublicSshKeysForAuthenticatedUser: ['GET /user/keys'],
            listSocialAccountsForAuthenticatedUser: ['GET /user/social_accounts'],
            listSocialAccountsForUser: ['GET /users/{username}/social_accounts'],
            listSshSigningKeysForAuthenticatedUser: ['GET /user/ssh_signing_keys'],
            listSshSigningKeysForUser: ['GET /users/{username}/ssh_signing_keys'],
            setPrimaryEmailVisibilityForAuthenticated: [
                'PATCH /user/email/visibility',
                {},
                { renamed: ['users', 'setPrimaryEmailVisibilityForAuthenticatedUser'] },
            ],
            setPrimaryEmailVisibilityForAuthenticatedUser: ['PATCH /user/email/visibility'],
            unblock: ['DELETE /user/blocks/{username}'],
            unfollow: ['DELETE /user/following/{username}'],
            updateAuthenticated: ['PATCH /user'],
        },
    }
    var endpoints_default = Endpoints
    var endpointMethodsMap = new Map()
    for (const [scope, endpoints] of Object.entries(endpoints_default)) {
        for (const [methodName, endpoint] of Object.entries(endpoints)) {
            const [route, defaults, decorations] = endpoint
            const [method, url] = route.split(/ /)
            const endpointDefaults = Object.assign(
                {
                    method,
                    url,
                },
                defaults
            )
            if (!endpointMethodsMap.has(scope)) {
                endpointMethodsMap.set(scope, new Map())
            }
            endpointMethodsMap.get(scope).set(methodName, {
                scope,
                methodName,
                endpointDefaults,
                decorations,
            })
        }
    }
    var handler = {
        has({ scope }, methodName) {
            return endpointMethodsMap.get(scope).has(methodName)
        },
        getOwnPropertyDescriptor(target, methodName) {
            return {
                value: this.get(target, methodName),
                configurable: true,
                writable: true,
                enumerable: true,
            }
        },
        defineProperty(target, methodName, descriptor) {
            Object.defineProperty(target.cache, methodName, descriptor)
            return true
        },
        deleteProperty(target, methodName) {
            delete target.cache[methodName]
            return true
        },
        ownKeys({ scope }) {
            return [...endpointMethodsMap.get(scope).keys()]
        },
        set(target, methodName, value) {
            return (target.cache[methodName] = value)
        },
        get({ octokit, scope, cache }, methodName) {
            if (cache[methodName]) {
                return cache[methodName]
            }
            const method = endpointMethodsMap.get(scope).get(methodName)
            if (!method) {
                return
            }
            const { endpointDefaults, decorations } = method
            if (decorations) {
                cache[methodName] = decorate(
                    octokit,
                    scope,
                    methodName,
                    endpointDefaults,
                    decorations
                )
            } else {
                cache[methodName] = octokit.request.defaults(endpointDefaults)
            }
            return cache[methodName]
        },
    }
    restEndpointMethods.VERSION = VERSION
    legacyRestEndpointMethods.VERSION = VERSION
})

// node_modules/@octokit/plugin-paginate-rest/dist-node/index.js
var require_dist_node10 = __commonJS((exports, module) => {
    var normalizePaginatedListResponse = (response) => {
        if (!response.data) {
            return {
                ...response,
                data: [],
            }
        }
        const responseNeedsNormalization =
            'total_count' in response.data && !('url' in response.data)
        if (!responseNeedsNormalization) return response
        const incompleteResults = response.data.incomplete_results
        const repositorySelection = response.data.repository_selection
        const totalCount = response.data.total_count
        delete response.data.incomplete_results
        delete response.data.repository_selection
        delete response.data.total_count
        const namespaceKey = Object.keys(response.data)[0]
        const data = response.data[namespaceKey]
        response.data = data
        if (typeof incompleteResults !== 'undefined') {
            response.data.incomplete_results = incompleteResults
        }
        if (typeof repositorySelection !== 'undefined') {
            response.data.repository_selection = repositorySelection
        }
        response.data.total_count = totalCount
        return response
    }
    var iterator = (octokit, route, parameters) => {
        const options =
            typeof route === 'function'
                ? route.endpoint(parameters)
                : octokit.request.endpoint(route, parameters)
        const requestMethod = typeof route === 'function' ? route : octokit.request
        const method = options.method
        const headers = options.headers
        let url = options.url
        return {
            [Symbol.asyncIterator]: () => ({
                async next() {
                    if (!url) return { done: true }
                    try {
                        const response = await requestMethod({ method, url, headers })
                        const normalizedResponse = normalizePaginatedListResponse(response)
                        url = ((normalizedResponse.headers.link || '').match(
                            /<([^>]+)>;\s*rel="next"/
                        ) || [])[1]
                        return { value: normalizedResponse }
                    } catch (error) {
                        if (error.status !== 409) throw error
                        url = ''
                        return {
                            value: {
                                status: 200,
                                headers: {},
                                data: [],
                            },
                        }
                    }
                },
            }),
        }
    }
    var paginate = (octokit, route, parameters, mapFn) => {
        if (typeof parameters === 'function') {
            mapFn = parameters
            parameters = undefined
        }
        return gather(
            octokit,
            [],
            iterator(octokit, route, parameters)[Symbol.asyncIterator](),
            mapFn
        )
    }
    var gather = (octokit, results, iterator2, mapFn) =>
        iterator2.next().then((result) => {
            if (result.done) {
                return results
            }
            let earlyExit = false
            function done() {
                earlyExit = true
            }
            results = results.concat(mapFn ? mapFn(result.value, done) : result.value.data)
            if (earlyExit) {
                return results
            }
            return gather(octokit, results, iterator2, mapFn)
        })
    var isPaginatingEndpoint = (arg) => {
        if (typeof arg === 'string') {
            return paginatingEndpoints.includes(arg)
        } else {
            return false
        }
    }
    var paginateRest = (octokit) => ({
        paginate: Object.assign(paginate.bind(null, octokit), {
            iterator: iterator.bind(null, octokit),
        }),
    })
    var __defProp2 = Object.defineProperty
    var __getOwnPropDesc = Object.getOwnPropertyDescriptor
    var __getOwnPropNames2 = Object.getOwnPropertyNames
    var __hasOwnProp2 = Object.prototype.hasOwnProperty
    var __export = (target, all) => {
        for (var name in all) __defProp2(target, name, { get: all[name], enumerable: true })
    }
    var __copyProps = (to, from, except, desc) => {
        if ((from && typeof from === 'object') || typeof from === 'function') {
            for (const key of __getOwnPropNames2(from))
                if (!__hasOwnProp2.call(to, key) && key !== except)
                    __defProp2(to, key, {
                        get: () => from[key],
                        enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable,
                    })
        }
        return to
    }
    var __toCommonJS = (mod) => __copyProps(__defProp2({}, '__esModule', { value: true }), mod)
    var dist_src_exports = {}
    __export(dist_src_exports, {
        composePaginateRest: () => composePaginateRest,
        isPaginatingEndpoint: () => isPaginatingEndpoint,
        paginateRest: () => paginateRest,
        paginatingEndpoints: () => paginatingEndpoints,
    })
    module.exports = __toCommonJS(dist_src_exports)
    var VERSION = '9.2.1'
    var composePaginateRest = Object.assign(paginate, {
        iterator,
    })
    var paginatingEndpoints = [
        'GET /advisories',
        'GET /app/hook/deliveries',
        'GET /app/installation-requests',
        'GET /app/installations',
        'GET /assignments/{assignment_id}/accepted_assignments',
        'GET /classrooms',
        'GET /classrooms/{classroom_id}/assignments',
        'GET /enterprises/{enterprise}/dependabot/alerts',
        'GET /enterprises/{enterprise}/secret-scanning/alerts',
        'GET /events',
        'GET /gists',
        'GET /gists/public',
        'GET /gists/starred',
        'GET /gists/{gist_id}/comments',
        'GET /gists/{gist_id}/commits',
        'GET /gists/{gist_id}/forks',
        'GET /installation/repositories',
        'GET /issues',
        'GET /licenses',
        'GET /marketplace_listing/plans',
        'GET /marketplace_listing/plans/{plan_id}/accounts',
        'GET /marketplace_listing/stubbed/plans',
        'GET /marketplace_listing/stubbed/plans/{plan_id}/accounts',
        'GET /networks/{owner}/{repo}/events',
        'GET /notifications',
        'GET /organizations',
        'GET /orgs/{org}/actions/cache/usage-by-repository',
        'GET /orgs/{org}/actions/permissions/repositories',
        'GET /orgs/{org}/actions/runners',
        'GET /orgs/{org}/actions/secrets',
        'GET /orgs/{org}/actions/secrets/{secret_name}/repositories',
        'GET /orgs/{org}/actions/variables',
        'GET /orgs/{org}/actions/variables/{name}/repositories',
        'GET /orgs/{org}/blocks',
        'GET /orgs/{org}/code-scanning/alerts',
        'GET /orgs/{org}/codespaces',
        'GET /orgs/{org}/codespaces/secrets',
        'GET /orgs/{org}/codespaces/secrets/{secret_name}/repositories',
        'GET /orgs/{org}/copilot/billing/seats',
        'GET /orgs/{org}/dependabot/alerts',
        'GET /orgs/{org}/dependabot/secrets',
        'GET /orgs/{org}/dependabot/secrets/{secret_name}/repositories',
        'GET /orgs/{org}/events',
        'GET /orgs/{org}/failed_invitations',
        'GET /orgs/{org}/hooks',
        'GET /orgs/{org}/hooks/{hook_id}/deliveries',
        'GET /orgs/{org}/installations',
        'GET /orgs/{org}/invitations',
        'GET /orgs/{org}/invitations/{invitation_id}/teams',
        'GET /orgs/{org}/issues',
        'GET /orgs/{org}/members',
        'GET /orgs/{org}/members/{username}/codespaces',
        'GET /orgs/{org}/migrations',
        'GET /orgs/{org}/migrations/{migration_id}/repositories',
        'GET /orgs/{org}/organization-roles/{role_id}/teams',
        'GET /orgs/{org}/organization-roles/{role_id}/users',
        'GET /orgs/{org}/outside_collaborators',
        'GET /orgs/{org}/packages',
        'GET /orgs/{org}/packages/{package_type}/{package_name}/versions',
        'GET /orgs/{org}/personal-access-token-requests',
        'GET /orgs/{org}/personal-access-token-requests/{pat_request_id}/repositories',
        'GET /orgs/{org}/personal-access-tokens',
        'GET /orgs/{org}/personal-access-tokens/{pat_id}/repositories',
        'GET /orgs/{org}/projects',
        'GET /orgs/{org}/properties/values',
        'GET /orgs/{org}/public_members',
        'GET /orgs/{org}/repos',
        'GET /orgs/{org}/rulesets',
        'GET /orgs/{org}/rulesets/rule-suites',
        'GET /orgs/{org}/secret-scanning/alerts',
        'GET /orgs/{org}/security-advisories',
        'GET /orgs/{org}/teams',
        'GET /orgs/{org}/teams/{team_slug}/discussions',
        'GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments',
        'GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}/reactions',
        'GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/reactions',
        'GET /orgs/{org}/teams/{team_slug}/invitations',
        'GET /orgs/{org}/teams/{team_slug}/members',
        'GET /orgs/{org}/teams/{team_slug}/projects',
        'GET /orgs/{org}/teams/{team_slug}/repos',
        'GET /orgs/{org}/teams/{team_slug}/teams',
        'GET /projects/columns/{column_id}/cards',
        'GET /projects/{project_id}/collaborators',
        'GET /projects/{project_id}/columns',
        'GET /repos/{owner}/{repo}/actions/artifacts',
        'GET /repos/{owner}/{repo}/actions/caches',
        'GET /repos/{owner}/{repo}/actions/organization-secrets',
        'GET /repos/{owner}/{repo}/actions/organization-variables',
        'GET /repos/{owner}/{repo}/actions/runners',
        'GET /repos/{owner}/{repo}/actions/runs',
        'GET /repos/{owner}/{repo}/actions/runs/{run_id}/artifacts',
        'GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}/jobs',
        'GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs',
        'GET /repos/{owner}/{repo}/actions/secrets',
        'GET /repos/{owner}/{repo}/actions/variables',
        'GET /repos/{owner}/{repo}/actions/workflows',
        'GET /repos/{owner}/{repo}/actions/workflows/{workflow_id}/runs',
        'GET /repos/{owner}/{repo}/activity',
        'GET /repos/{owner}/{repo}/assignees',
        'GET /repos/{owner}/{repo}/branches',
        'GET /repos/{owner}/{repo}/check-runs/{check_run_id}/annotations',
        'GET /repos/{owner}/{repo}/check-suites/{check_suite_id}/check-runs',
        'GET /repos/{owner}/{repo}/code-scanning/alerts',
        'GET /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}/instances',
        'GET /repos/{owner}/{repo}/code-scanning/analyses',
        'GET /repos/{owner}/{repo}/codespaces',
        'GET /repos/{owner}/{repo}/codespaces/devcontainers',
        'GET /repos/{owner}/{repo}/codespaces/secrets',
        'GET /repos/{owner}/{repo}/collaborators',
        'GET /repos/{owner}/{repo}/comments',
        'GET /repos/{owner}/{repo}/comments/{comment_id}/reactions',
        'GET /repos/{owner}/{repo}/commits',
        'GET /repos/{owner}/{repo}/commits/{commit_sha}/comments',
        'GET /repos/{owner}/{repo}/commits/{commit_sha}/pulls',
        'GET /repos/{owner}/{repo}/commits/{ref}/check-runs',
        'GET /repos/{owner}/{repo}/commits/{ref}/check-suites',
        'GET /repos/{owner}/{repo}/commits/{ref}/status',
        'GET /repos/{owner}/{repo}/commits/{ref}/statuses',
        'GET /repos/{owner}/{repo}/contributors',
        'GET /repos/{owner}/{repo}/dependabot/alerts',
        'GET /repos/{owner}/{repo}/dependabot/secrets',
        'GET /repos/{owner}/{repo}/deployments',
        'GET /repos/{owner}/{repo}/deployments/{deployment_id}/statuses',
        'GET /repos/{owner}/{repo}/environments',
        'GET /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies',
        'GET /repos/{owner}/{repo}/environments/{environment_name}/deployment_protection_rules/apps',
        'GET /repos/{owner}/{repo}/events',
        'GET /repos/{owner}/{repo}/forks',
        'GET /repos/{owner}/{repo}/hooks',
        'GET /repos/{owner}/{repo}/hooks/{hook_id}/deliveries',
        'GET /repos/{owner}/{repo}/invitations',
        'GET /repos/{owner}/{repo}/issues',
        'GET /repos/{owner}/{repo}/issues/comments',
        'GET /repos/{owner}/{repo}/issues/comments/{comment_id}/reactions',
        'GET /repos/{owner}/{repo}/issues/events',
        'GET /repos/{owner}/{repo}/issues/{issue_number}/comments',
        'GET /repos/{owner}/{repo}/issues/{issue_number}/events',
        'GET /repos/{owner}/{repo}/issues/{issue_number}/labels',
        'GET /repos/{owner}/{repo}/issues/{issue_number}/reactions',
        'GET /repos/{owner}/{repo}/issues/{issue_number}/timeline',
        'GET /repos/{owner}/{repo}/keys',
        'GET /repos/{owner}/{repo}/labels',
        'GET /repos/{owner}/{repo}/milestones',
        'GET /repos/{owner}/{repo}/milestones/{milestone_number}/labels',
        'GET /repos/{owner}/{repo}/notifications',
        'GET /repos/{owner}/{repo}/pages/builds',
        'GET /repos/{owner}/{repo}/projects',
        'GET /repos/{owner}/{repo}/pulls',
        'GET /repos/{owner}/{repo}/pulls/comments',
        'GET /repos/{owner}/{repo}/pulls/comments/{comment_id}/reactions',
        'GET /repos/{owner}/{repo}/pulls/{pull_number}/comments',
        'GET /repos/{owner}/{repo}/pulls/{pull_number}/commits',
        'GET /repos/{owner}/{repo}/pulls/{pull_number}/files',
        'GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews',
        'GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}/comments',
        'GET /repos/{owner}/{repo}/releases',
        'GET /repos/{owner}/{repo}/releases/{release_id}/assets',
        'GET /repos/{owner}/{repo}/releases/{release_id}/reactions',
        'GET /repos/{owner}/{repo}/rules/branches/{branch}',
        'GET /repos/{owner}/{repo}/rulesets',
        'GET /repos/{owner}/{repo}/rulesets/rule-suites',
        'GET /repos/{owner}/{repo}/secret-scanning/alerts',
        'GET /repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}/locations',
        'GET /repos/{owner}/{repo}/security-advisories',
        'GET /repos/{owner}/{repo}/stargazers',
        'GET /repos/{owner}/{repo}/subscribers',
        'GET /repos/{owner}/{repo}/tags',
        'GET /repos/{owner}/{repo}/teams',
        'GET /repos/{owner}/{repo}/topics',
        'GET /repositories',
        'GET /repositories/{repository_id}/environments/{environment_name}/secrets',
        'GET /repositories/{repository_id}/environments/{environment_name}/variables',
        'GET /search/code',
        'GET /search/commits',
        'GET /search/issues',
        'GET /search/labels',
        'GET /search/repositories',
        'GET /search/topics',
        'GET /search/users',
        'GET /teams/{team_id}/discussions',
        'GET /teams/{team_id}/discussions/{discussion_number}/comments',
        'GET /teams/{team_id}/discussions/{discussion_number}/comments/{comment_number}/reactions',
        'GET /teams/{team_id}/discussions/{discussion_number}/reactions',
        'GET /teams/{team_id}/invitations',
        'GET /teams/{team_id}/members',
        'GET /teams/{team_id}/projects',
        'GET /teams/{team_id}/repos',
        'GET /teams/{team_id}/teams',
        'GET /user/blocks',
        'GET /user/codespaces',
        'GET /user/codespaces/secrets',
        'GET /user/emails',
        'GET /user/followers',
        'GET /user/following',
        'GET /user/gpg_keys',
        'GET /user/installations',
        'GET /user/installations/{installation_id}/repositories',
        'GET /user/issues',
        'GET /user/keys',
        'GET /user/marketplace_purchases',
        'GET /user/marketplace_purchases/stubbed',
        'GET /user/memberships/orgs',
        'GET /user/migrations',
        'GET /user/migrations/{migration_id}/repositories',
        'GET /user/orgs',
        'GET /user/packages',
        'GET /user/packages/{package_type}/{package_name}/versions',
        'GET /user/public_emails',
        'GET /user/repos',
        'GET /user/repository_invitations',
        'GET /user/social_accounts',
        'GET /user/ssh_signing_keys',
        'GET /user/starred',
        'GET /user/subscriptions',
        'GET /user/teams',
        'GET /users',
        'GET /users/{username}/events',
        'GET /users/{username}/events/orgs/{org}',
        'GET /users/{username}/events/public',
        'GET /users/{username}/followers',
        'GET /users/{username}/following',
        'GET /users/{username}/gists',
        'GET /users/{username}/gpg_keys',
        'GET /users/{username}/keys',
        'GET /users/{username}/orgs',
        'GET /users/{username}/packages',
        'GET /users/{username}/projects',
        'GET /users/{username}/received_events',
        'GET /users/{username}/received_events/public',
        'GET /users/{username}/repos',
        'GET /users/{username}/social_accounts',
        'GET /users/{username}/ssh_signing_keys',
        'GET /users/{username}/starred',
        'GET /users/{username}/subscriptions',
    ]
    paginateRest.VERSION = VERSION
})

// node_modules/@actions/github/lib/utils.js
var require_utils3 = __commonJS((exports) => {
    var getOctokitOptions = (token, options) => {
        const opts = Object.assign({}, options || {})
        const auth = Utils.getAuthString(token, opts)
        if (auth) {
            opts.auth = auth
        }
        return opts
    }
    var __createBinding =
        (exports && exports.__createBinding) ||
        (Object.create
            ? (o, m, k, k2) => {
                  if (k2 === undefined) k2 = k
                  var desc = Object.getOwnPropertyDescriptor(m, k)
                  if (
                      !desc ||
                      ('get' in desc ? !m.__esModule : desc.writable || desc.configurable)
                  ) {
                      desc = { enumerable: true, get: () => m[k] }
                  }
                  Object.defineProperty(o, k2, desc)
              }
            : (o, m, k, k2) => {
                  if (k2 === undefined) k2 = k
                  o[k2] = m[k]
              })
    var __setModuleDefault =
        (exports && exports.__setModuleDefault) ||
        (Object.create
            ? (o, v) => {
                  Object.defineProperty(o, 'default', { enumerable: true, value: v })
              }
            : (o, v) => {
                  o['default'] = v
              })
    var __importStar =
        (exports && exports.__importStar) ||
        ((mod) => {
            if (mod && mod.__esModule) return mod
            var result = {}
            if (mod != null) {
                for (var k in mod)
                    if (k !== 'default' && Object.prototype.hasOwnProperty.call(mod, k))
                        __createBinding(result, mod, k)
            }
            __setModuleDefault(result, mod)
            return result
        })
    Object.defineProperty(exports, '__esModule', { value: true })
    exports.getOctokitOptions = exports.GitHub = exports.defaults = exports.context = undefined
    var Context = __importStar(require_context())
    var Utils = __importStar(require_utils2())
    var core_1 = require_dist_node8()
    var plugin_rest_endpoint_methods_1 = require_dist_node9()
    var plugin_paginate_rest_1 = require_dist_node10()
    exports.context = new Context.Context()
    var baseUrl = Utils.getApiBaseUrl()
    exports.defaults = {
        baseUrl,
        request: {
            agent: Utils.getProxyAgent(baseUrl),
            fetch: Utils.getProxyFetch(baseUrl),
        },
    }
    exports.GitHub = core_1.Octokit.plugin(
        plugin_rest_endpoint_methods_1.restEndpointMethods,
        plugin_paginate_rest_1.paginateRest
    ).defaults(exports.defaults)
    exports.getOctokitOptions = getOctokitOptions
})

// node_modules/@actions/github/lib/github.js
var require_github = __commonJS((exports) => {
    var getOctokit = (token, options, ...additionalPlugins) => {
        const GitHubWithPlugins = utils_1.GitHub.plugin(...additionalPlugins)
        return new GitHubWithPlugins((0, utils_1.getOctokitOptions)(token, options))
    }
    var __createBinding =
        (exports && exports.__createBinding) ||
        (Object.create
            ? (o, m, k, k2) => {
                  if (k2 === undefined) k2 = k
                  var desc = Object.getOwnPropertyDescriptor(m, k)
                  if (
                      !desc ||
                      ('get' in desc ? !m.__esModule : desc.writable || desc.configurable)
                  ) {
                      desc = { enumerable: true, get: () => m[k] }
                  }
                  Object.defineProperty(o, k2, desc)
              }
            : (o, m, k, k2) => {
                  if (k2 === undefined) k2 = k
                  o[k2] = m[k]
              })
    var __setModuleDefault =
        (exports && exports.__setModuleDefault) ||
        (Object.create
            ? (o, v) => {
                  Object.defineProperty(o, 'default', { enumerable: true, value: v })
              }
            : (o, v) => {
                  o['default'] = v
              })
    var __importStar =
        (exports && exports.__importStar) ||
        ((mod) => {
            if (mod && mod.__esModule) return mod
            var result = {}
            if (mod != null) {
                for (var k in mod)
                    if (k !== 'default' && Object.prototype.hasOwnProperty.call(mod, k))
                        __createBinding(result, mod, k)
            }
            __setModuleDefault(result, mod)
            return result
        })
    Object.defineProperty(exports, '__esModule', { value: true })
    exports.getOctokit = exports.context = undefined
    var Context = __importStar(require_context())
    var utils_1 = require_utils3()
    exports.context = new Context.Context()
    exports.getOctokit = getOctokit
})

// src/index.ts
var core = __toESM(require_core(), 1)
var github = __toESM(require_github(), 1)
var run = async () => {
    try {
        const prtitle = github.context.payload.pull_request?.title
        core.setOutput('pr-title', prtitle)
    } catch (error) {
        core.setFailed(error.message)
    }
}
run()
