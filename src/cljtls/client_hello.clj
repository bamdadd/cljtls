(ns cljtls.client-hello)

(defrecord RecordHeader [type protocol-version record-payload-len])
(defrecord HandshakeHeader [handshake-message-type payload-len])
(defrecord ClientVersion [client-version])
(defrecord ClientRandom [client-random])
(defrecord SessionId [session-id])
(defrecord CipherSuites [size ciphers])
(defrecord CompressionMethods [size value])
(defrecord Extensions [size value])

(defrecord ClientHello [record-header
                        handshake-header
                        client-version
                        client-random
                        session-id
                        cipher-suites
                        compression-methods
                        extensions])
