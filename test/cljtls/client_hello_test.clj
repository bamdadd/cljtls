(ns cljtls.client-hello-test
  (:require [clojure.test :refer :all]
            [cljtls.client-hello :refer :all])
  (:import [cljtls.client_hello
            RecordHeader
            HandshakeHeader ClientVersion
            ClientRandom
            SessionId
            CipherSuites
            CompressionMethods
            Extensions]))

(deftest client-hello-test
  (def hello
    (byte-array
      [0x16 0x03 0x01 0x00 0xa5 0x01 0x00 0x00 0xa1 0x03 0x03 0x00
       0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x0a 0x0b 0x0c
       0x0d 0x0e 0x0f 0x10 0x11 0x12 0x13 0x14 0x15 0x16 0x17 0x18
       0x19 0x1a 0x1b 0x1c 0x1d 0x1e 0x1f 0x00 0x00 0x20 0xcc 0xa8
       0xcc 0xa9 0xc0 0x2f 0xc0 0x30 0xc0 0x2b 0xc0 0x2c 0xc0 0x13
       0xc0 0x09 0xc0 0x14 0xc0 0x0a 0x00 0x9c 0x00 0x9d 0x00 0x2f
       0x00 0x35 0xc0 0x12 0x00 0x0a 0x01 0x00 0x00 0x58 0x00 0x00
       0x00 0x18 0x00 0x16 0x00 0x00 0x13 0x65 0x78 0x61 0x6d 0x70
       0x6c 0x65 0x2e 0x75 0x6c 0x66 0x68 0x65 0x69 0x6d 0x2e 0x6e
       0x65 0x74 0x00 0x05 0x00 0x05 0x01 0x00 0x00 0x00 0x00 0x00
       0x0a 0x00 0x0a 0x00 0x08 0x00 0x1d 0x00 0x17 0x00 0x18 0x00
       0x19 0x00 0x0b 0x00 0x02 0x01 0x00 0x00 0x0d 0x00 0x12 0x00
       0x10 0x04 0x01 0x04 0x03 0x05 0x01 0x05 0x03 0x06 0x01 0x06
       0x03 0x02 0x01 0x02 0x03 0xff 0x01 0x00 0x01 0x00 0x00 0x12
       0x00 0x00]))

  (testing "client-hello"
    (testing "record header"
      (let [record-header (RecordHeader. 0x16 [0x03 0x01] [0x00 0xa5])]
        (is (= (:type record-header) 0x16))
        (is (= (:protocol-version record-header) [0x03 0x01]))
        (is (= (:record-payload-len record-header) [0x00 0xa5]))))

    (testing "handshake header"
      (let [handshake-header (HandshakeHeader. 0x01 [0x00 0x00 0xa1])]
        (is (= (:handshake-message-type handshake-header) 0x01))
        (is (= (:payload-len handshake-header) [0x00 0x00 0xa1]))))

    (testing "client version"
      (let [client-version (ClientVersion. [0x03 0x03])]
        (is (= (:client-version client-version) [0x03 0x03]))))


    (testing "client random"
      (let [client-random
            (ClientRandom.
              [0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x0a 0x0b 0x0c
               0x0d 0x0e 0x0f 0x10 0x11 0x12 0x13 0x14 0x15 0x16 0x17 0x18 0x19
               0x1a 0x1b 0x1c 0x1d 0x1e 0x1f])]
        (is (= (:client-random client-random)
              [0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x0a 0x0b 0x0c
               0x0d 0x0e 0x0f 0x10 0x11 0x12 0x13 0x14 0x15 0x16 0x17 0x18 0x19
               0x1a 0x1b 0x1c 0x1d 0x1e 0x1f]))))


    (testing "session id"
      (let [session-id (SessionId. 0x00)]
        (is (= (:session-id session-id) 0x00))))

    (testing "cipher suites"
      (let [cipher-suites
            (CipherSuites.
              [0x00 0x20]
              [0xcc 0xa8                                    ;ECDHE-RSA-CHACHA20-POLY1305-SHA256
               0xcc 0xa9                                    ;ECDHE-ECDSA-CHACHA20-POLY1305-SHA256
               0xc0 0x2f                                    ;ECDHE-RSA-AES128-GCM-SHA256
               0xc0 0x30                                    ;ECDHE-RSA-AES256-GCM-SHA384
               0xc0 0x2b                                    ;ECDHE-ECDSA-AES128-GCM-SHA256
               0xc0 0x2c                                    ;ECDHE-ECDSA-AES256-GCM-SHA384
               0xc0 0x13                                    ;ECDHE-RSA-AES128-SHA
               0xc0 0x09                                    ;ECDHE-ECDSA-AES128-SHA
               0xc0 0x14                                    ;ECDHE-RSA-AES256-SHA
               0xc0 0x0a                                    ;ECDHE-ECDSA-AES256-SHA
               0x00 0x9c                                    ;RSA-AES128-GCM-SHA256
               0x00 0x9d                                    ;RSA-AES256-GCM-SHA384
               0x00 0x2f                                    ;RSA-AES128-SHA
               0x00 0x35                                    ;RSA-AES256-SHA
               0xc0 0x12                                    ;ECDHE-RSA-3DES-EDE-SHA
               0x00 0x0a                                    ;RSA-3DES-EDE-SHA
               ])]
        (is (= (:size cipher-suites) [0x00 0x20]))
        (is (= (:ciphers cipher-suites)
              [0xcc 0xa8
               0xcc 0xa9
               0xc0 0x2f
               0xc0 0x30
               0xc0 0x2b
               0xc0 0x2c
               0xc0 0x13
               0xc0 0x09
               0xc0 0x14
               0xc0 0x0a
               0x00 0x9c
               0x00 0x9d
               0x00 0x2f
               0x00 0x35
               0xc0 0x12
               0x00 0x0a]))))


    (testing "Compression Methods"
      (let [compression-methods
            (CompressionMethods.
              0x01 0x00)]
        (is (= (:size compression-methods) 0x01))
        (is (= (:value compression-methods) 0x00))))

    (testing "Extensions"
      (let [extensions
            (Extensions.
              [0x00 0x58] nil)]
        (is (= (:size extensions) [0x00 0x58]))
        (is (= (:value extensions) nil))))
    ))



