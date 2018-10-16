(ns cljtls.client-hello)

(defrecord RecordHeader [type protocol-version record-payload-len])
(defrecord HandshakeHeader [handshake-message-type payload-len])
(defrecord ClientVersion [client-version])
(defrecord ClientRandom [client-random])
(defrecord SessionId [session-id])
(defrecord CipherSuites [size ciphers])
(defrecord CompressionMethods [size value])
(defrecord Extensions [size value])
(defrecord ServerNameExtension
  [extension-type
   data-follows-bytes
   first-list-entry-bytes
   list-entry-type
   bytes-of-entry-follows
   server-name])

(defrecord StatusRequestExtension
  [extension-type
   data-follows-bytes
   certificate-status-type
   responder-id-size
   request-extension-size])

(defrecord SupportedGroupsExtension
  [extension-type
   data-follows-bytes
   data-size
   supported-curves])

(defrecord ECPointFormat
  [extension-type
   data-follows-bytes
   data-size
   value-for-uncompressed-form])

(defrecord SignatureAlgorithmsExtension
  [extension-type
   data-follows-bytes
   data-size
   supported-algorithms])

(defrecord RenegotiationInfoExtension
  [extension-type
   data-follows-bytes
   data-size
   renegotiation])

(defrecord SignedCertificateTimestampExtension
  [extension-type
   data-follows-bytes
   data])

(defrecord ClientHello
  [record-header
   handshake-header
   client-version
   client-random
   session-id
   cipher-suites
   compression-methods
   extensions])
